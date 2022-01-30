//   Don't translate these defines You can add, and renumber as long as 
//   they match the order of the array below.  The defines must
//   match the ones in the source code.
//

#define ERR_CANT_OPEN_AUTH       1   // Can't open authentication database
#define ERR_TOO_MANY_ACTION      2   // Too many actions before login
#define ERR_RD_TIMEOUT           3   // Read Timeout
#define ERR_INVALID_COMMAND      4   // Invalid Command
#define ERR_TOO_MANY_LOGIN       5   // Too many invalid login attempts
#define ERR_EMAIL_REQD           6   // Email Address Required
#define ERR_PASSWORD_REQD        7   // Password Required
#define ERR_INVALID_LOGIN        8   // Invalid Login
#define ERR_NOT_AUTHORIZED       9   // Not Authorized
#define ERR_INVALID_EMAIL       10   // Invalid Email Address
#define ERR_NOT_AUTH_DOMAIN     11   // Not Authorized for domain
#define ERR_NO_USER             12   // User does not exist
#define ERR_DOMAIN_REQD         13   // Domain Required
#define ERR_ALIAS_REQD          14   // Alias Name Required
#define ERR_INVALID_ALIAS       15   // Invalid Alias Name Supplied
#define ERR_ALIAS_LINE_REQD     16   // Alias Line Required
#define ERR_ALIAS_INSERT_FAIL   17   // Alias Insertion Failed
#define ERR_ALIAS_REMOVE_FAIL   18   // Alias Removal Failed
#define ERR_ALIAS_DELETE_FAIL   19   // Alias Deletion Failed
#define ERR_INVALID_DIR_DOTDOT  20   // Invalid Directory.  .. not allowed in path
#define ERR_INVALID_DIR_PCT     21   // Invalid Directory.  % not allowed in path
#define ERR_INVALID_DIR_SLASH   22   // Invalid Directory.  Do you need a trailing '/'?
#define ERR_INVALID_DIR_AT      23   // Invalid Directory. Found / before @
#define ERR_INVALID_DIR_PARSE   24   // Invalid Directory. Can't parse email address
#define ERR_INVALID_DIR_UNK     25   // Invalid Directory. Unknown email address
#define ERR_UNAUTH_DIR          26   // Unauthorized Directory.
#define ERR_DIR_REQD            27   // Directory Required.
#define ERR_SOURCE_REQD         28   // Source File Name Required
#define ERR_DEST_REQD           29   // Destination File Name Required
#define ERR_FNAME_REQD          30   // Filename Required
#define ERR_NO_OPEN_ASSIGN      31   // Could not open assign file
#define ERR_IP_REQD             32   // IP Required
#define ERR_NOT_AVAIL           33   // Not Available
#define ERR_NO_GET_LIMITS       34   // Could not get limits
#define ERR_NO_SET_LIMITS       35   // Could not set limits
#define ERR_NOT_IMPLEMENT       36   // Not implemented yet
#define ERR_IP_REQUIRED         37   // Not implemented yet
#define ERR_INVALID_DOMAIN      38   // Not implemented yet



//  Translate just this array, but not the comments

const char *ErrorMessages[] = {
   "Dummy entry so it starts with 1",                 //  dummy entry...
   "Can't open authentication database",              //  CANT_OPEN_AUTH       1 
   "Too many actions before login",                   //  TOO_MANY_ACTION      2 
   "Read Timeout",                                    //  RD_TIMEOUT           3 
   "Invalid Command",                                 //  INVALID_COMMAND      4   
   "Too many invalid login attempts",                 //  TOO_MANY_LOGIN       5   
   "Email Address Required",                          //  EMAIL_REQD           6   
   "Password Required",                               //  PASSWORD_REQD        7   
   "Invalid Login",                                   //  INVALID_LOGIN        8   
   "Not Authorized",                                  //  NOT_AUTHORIZED       9   
   "Invalid Email Address",                           //  INVALID_EMAIL       10   
   "Not Authorized for domain",                       //  NOT_AUTH_DOMAIN     11   
   "User does not exist",                             //  NO_USER             12   
   "Domain Required",                                 //  DOMAIN_REQD         13   
   "Alias Name Required",                             //  ALIAS_REQD          14   
   "Invalid Alias Name Supplied",                     //  INVALID_ALIAS       15   
   "Alias Line Required",                             //  ALIAS_LINE_REQD     16   
   "Alias Insertion Failed",                          //  ALIAS_INSERT_FAIL   17   
   "Alias Removal Failed",                            //  ALIAS_REMOVE_FAIL   18   
   "Alias Deletion Failed",                           //  ALIAS_DELETE_FAIL   19   
   "Invalid Directory.  .. not allowed in path",      //  INVALID_DIR_DOTDOT  20   
   "Invalid Directory.  % not allowed in path",       //  INVALID_DIR_PCT     21   
   "Invalid Directory.  Do you need a trailing '/'?", //  INVALID_DIR_SLASH   22   
   "Invalid Directory. Found / before @",             //  INVALID_DIR_AT      23   
   "Invalid Directory. Can't parse email address",    //  INVALID_DIR_PARSE   24   
   "Invalid Directory. Unknown email address",        //  INVALID_DIR_UNK     25   
   "Unauthorized Directory.",                         //  UNAUTH_DIR          26   
   "Directory Required.",                             //  DIR_REQD            27   
   "Source File Name Required",                       //  SOURCE_REQD         28   
   "Destination File Name Required",                  //  DEST_REQD           29   
   "Filename Required",                               //  FNAME_REQD          30   
   "Could not open assign file",                      //  NO_OPEN_ASSIGN      31   
   "IP Required",                                     //  IP_REQD             32   
   "Not Available",                                   //  NOT_AVAIL           33   
   "Could not get limits",                            //  NO_GET_LIMITS       34   
   "Could not set limits",                            //  NO_SET_LIMITS       35   
   "Not Implemented yet",                             //  NOT_IMPLEMENT       36   
};
