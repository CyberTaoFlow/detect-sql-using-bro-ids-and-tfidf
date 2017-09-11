#! Anamoly detection of SQL attacks

@load base/frameworks/notice
@load base/protocols/ssh
@load base/protocols/http

module HTTP;
export {
	redef enum Notice::Type += {
		SQL_URI_Injection_Attack,
		SQL_Post_Injection_Attack,
	};
 
	## URL message input
	type UMessage: record
	{	 
		text: string;       ## The actual URL body
	}; 
	
	const match_sql_uri = /[']/ &redef;
	const match_sql_uri1 = /[']/ &redef;
	const match_sql_uri2 = /[0-9]/ &redef;
	const match_sql_body =  /[']/     &redef;
	
	const match_sql_injection_uri =
		  /[\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/
		| /[\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/
		| /[\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/
		| /\/\*![[:digit:]]{5}.*?\*\// &redef;

	global ascore:count  &redef;
	global http_body:string &redef;
	redef record Info += {
		## Variable names extracted from all cookies.
		post_vars: vector of string &optional &log;
	}; 
} 

function record_match(msg: UMessage): string
{
	local match_data: string;
	match_data = "";
	if(|msg$text|>10)
	{
		if(match_sql_injection_uri in msg$text)
		match_data = string_cat(match_data, "alert;");

	}
	return match_data;
}


function calculate_score(match_data: string): count
{
	return |split_string_all(match_data, /;/)|/2;
}


### parse body
function parse_body(data: string)  : UMessage
{   local msg: UMessage;
	local array = split(data, /password=/);
	for( i in array)
   	{ 
		local val = array[i];
		msg$text = val;
   	} 

	print msg;
 } 

## Parse URI 
function parse_uri(data: string) : UMessage
{ 
	local msg: UMessage;

	local array = split(data, /id=/);                 
	for ( i in array )
	{ 
		local val = array[i];
		msg$text = val;

	} 

	if(i == 2)
	{ 
		return msg;  # returns msg
	} 	
	else 
	{ 
		msg$text = "";
		return msg;
	} 
} 

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=5
{ 
	local msg:UMessage;
	ascore = 1;
 	

	http_body = data; 
	## GET SQL IN REQUEST BODY
	
	print http_body;

	msg = parse_uri(http_body);

	print msg;

	if(|msg$text| > 10)
		++ascore;
	if(match_sql_body in msg$text)
	{ 
		++ascore;
	
		if(match_sql_uri1 in msg$text)
			++ascore;
	} 
	
	print ascore;

	if ( ascore >= 3)
	{ 
		NOTICE([$note=SQL_Post_Injection_Attack,
		$conn=c,
		$msg=fmt("SQL Attack from %s to destination: %s with Attack string %s and post data %s", c$id$orig_h, c$id$resp_h, c$http$uri, http_body)]);
	} 
	

} 

event http_request(c: connection, method: string, original_URI: string,
unescaped_URI: string, version: string) &priority=3
{ 
	local msg:UMessage;
	local body:UMessage;

	ascore = 1;

	# GET SQL IN HTTP REQUEST HEADER

	msg = parse_uri(c$http$uri);

	# Test for string length
	if ( |msg$text| > 2)    
		++ascore;            

	if(match_sql_uri in msg$text)
	{ 
		++ascore;
		if(match_sql_uri1 in msg$text)
			++ascore;
	} 
	
	if(match_sql_uri2 in msg$text && |msg$text| > 2)
	{	 
		++ascore;
	}
 
	if ( ascore >= 3)
	{ 

		NOTICE([$note=SQL_URI_Injection_Attack,
		$conn=c,
		$msg=fmt("SQL Attack from %s to destination: %s with Attack string %s", c$id$orig_h, c$id$resp_h, c$http$uri)]);
	} 
}
