/*******************************************************************************************************
  password_query and user_query procedures for dovecot's sql auth in case of --disable-many-domains.
  It supports aliasdomains and mysql-limits.

  More info here
  https://notes.sagredo.eu/en/qmail-notes-185/dovecot-vpopmail-auth-driver-removal-migrating-to-the-sql-driver-241.html

  By Roberto Puzzanghera

######  auth-sql.conf.ext

passdb {
  driver = sql
  args = /usr/local/dovecot/etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = prefetch
}

# This is for LDA.
userdb {
  driver = sql
  args = /usr/local/dovecot/etc/dovecot/dovecot-sql.conf.ext
}

##### dovecot-sql.conf.ext

password_query = CALL dovecot_password_query_disable_many_domains('%n','%d','127.0.0.1','%r','%a')
user_query = CALL dovecot_user_query_disable_many_domains('%n','%d')

 ***************************************************************************************************/


/****************************************************************
  Returns the domain table
 ****************************************************************/
DROP FUNCTION IF EXISTS `get_domain_table`;

DELIMITER $$
CREATE FUNCTION `get_domain_table`(`d` VARCHAR(100)) RETURNS varchar(100) CHARSET latin1
BEGIN

   DECLARE domain_table varchar(100);
   SET domain_table = dot2underscore(get_real_domain(d));

   RETURN domain_table;

END$$
DELIMITER ;


/****************************************************************
  Replaces dots and "-" with undescores in domain name
 ****************************************************************/
DROP FUNCTION IF EXISTS `dot2underscore`;

DELIMITER $$
CREATE FUNCTION `dot2underscore`(`d` VARCHAR(100)) RETURNS varchar(100) CHARSET latin1
BEGIN

   RETURN REPLACE(REPLACE(d, ".", "_"), "-", "_");

END$$
DELIMITER ;


/*******************************************************************
  Returns the real domain given an alias domain or the domain name
  if it's not an alias.
 *******************************************************************/
DROP FUNCTION IF EXISTS `get_real_domain`;

DELIMITER $$
CREATE FUNCTION `get_real_domain`(`d` VARCHAR(100)) RETURNS varchar(100) CHARSET latin1
BEGIN
   DECLARE real_domain varchar(100);

   IF NOT
      (SELECT 1 FROM INFORMATION_SCHEMA.TABLES
      WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=dot2underscore(d))
   IS NULL THEN
      SET real_domain = d;

   ELSEIF NOT
      (SELECT 1 FROM aliasdomains WHERE alias=d)
   IS NULL THEN
      SELECT domain INTO real_domain FROM aliasdomains WHERE alias=d;

   ELSE
   SET real_domain = NULL;

   END IF;

   RETURN real_domain;

END$$
DELIMITER ;


/**************************************************************************
  Stored procedure for password_query in case of "disabled many domains"
 **************************************************************************/
DROP PROCEDURE IF EXISTS `dovecot_password_query_disable_many_domains`;

DELIMITER $$
CREATE PROCEDURE `dovecot_password_query_disable_many_domains`(IN `name` VARCHAR(255), IN `domain` VARCHAR(255), IN `webmail_ip` VARCHAR(255), IN `remote_ip` VARCHAR(255), IN `port` INT)
BEGIN
DECLARE vpopmail varchar(256);
SET vpopmail = get_domain_table(domain);

IF (vpopmail) IS NULL THEN
   SET @SQL = "SELECT NULL";
ELSE
	SET @SQL = CONCAT("SELECT CONCAT(",vpopmail,".pw_name, '@', '",domain,"') AS user,",
	vpopmail,".pw_passwd AS password,",
	vpopmail,".pw_dir AS userdb_home,
	89 AS userdb_uid,
	89 AS userdb_gid,
	CONCAT('*:bytes=', REPLACE(SUBSTRING_INDEX(",vpopmail,".pw_shell, 'S', 1), 'NOQUOTA', '0')) AS userdb_quota_rule
	FROM ",vpopmail,"
	LEFT JOIN limits ON limits.domain='",get_real_domain(domain),"'
	WHERE ",vpopmail,".pw_name='",name,"'
	AND
	('",port,"'!='995' OR !(",vpopmail,".pw_gid & 2))
	AND
	('",remote_ip,"'!='",webmail_ip,"' OR !(",vpopmail,".pw_gid & 4))
	AND
	('",remote_ip,"'='",webmail_ip,"' OR '",port,"'!='993' OR !(",vpopmail,".pw_gid & 8))
	AND
	('",remote_ip,"'!='",webmail_ip,"' OR COALESCE(disable_webmail,0)!=1)
	AND
	('",remote_ip,"'='",webmail_ip,"' OR COALESCE(disable_imap,0)!=1)");
END IF;

PREPARE sql_code FROM @SQL;
EXECUTE sql_code;
DEALLOCATE PREPARE sql_code;

END$$
DELIMITER ;


/**************************************************************************
  Stored procedure for user_query in case of "disabled many domains"
 **************************************************************************/
DROP PROCEDURE IF EXISTS `dovecot_user_query_disable_many_domains`;

DELIMITER $$
CREATE PROCEDURE `dovecot_user_query_disable_many_domains`(IN `name` VARCHAR(255), IN `domain` VARCHAR(255))
BEGIN
DECLARE vpopmail varchar(256);
SET vpopmail = get_domain_table(domain);

IF (vpopmail) IS NULL THEN
	SET @SQL = "SELECT NULL";
ELSE
	set @SQL = concat("SELECT ",vpopmail,".pw_dir AS home, 89 AS uid, 89 AS gid FROM ",vpopmail," where ",vpopmail,".pw_name='",name,"'");
END IF;

PREPARE sql_code FROM @SQL;
EXECUTE sql_code;
DEALLOCATE PREPARE sql_code;

END$$
DELIMITER ;
