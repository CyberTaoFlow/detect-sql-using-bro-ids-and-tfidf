#! Anomaly detection of SQL attacks

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
	
	const match_sql_body = /[']/ &redef;
	const match_sql_body2 = /[*]/ &redef;
	const match_sql_body3 = /[%]/ &redef;
	const match_sql_body4 = /[#]/ &redef;
	const match_sql_body5 = /[(]/ &redef;
	const match_sql_body6 = /[)]/ &redef;
	const match_sql_body7 = /[+]/ &redef;
	const match_sql_body8 = /[,]/ &redef;
	const match_sql_body9 = /[-]/ &redef;
	const match_sql_body10 = /[:]/ &redef;
	const match_sql_body11 = /[;]/ &redef;
	const match_sql_body12 = /[>]/ &redef;
	const match_sql_body13 = /[<]/ &redef;
	const match_sql_body14 = /[=]/ &redef;
	const match_sql_body15 = /[_]/ &redef;	
	const match_sql_body_numbers = /[0-9]/ &redef;

	const match_sql_injection_uri1 = /[\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT]|[cC][oO][nN][cC][aA][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+/ &redef;

	const match_sql_injection_uri2 = /[\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/ &redef;

	const match_sql_injection_uri3 = /[\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/ &redef;

	const match_sql_injection_uri4 = /[\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/ &redef;

	const match_sql_injection_uri5 = /[\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/ &redef;

	const match_sql_injection_uri6 = /\/\*![[:digit:]]{5}.*?\*\// &redef;

	global ascore:count  &redef;
	global threshold:int  &redef;
	global http_body:string &redef;
	redef record Info += {
		## Variable names extracted from all cookies.
		post_vars: vector of string &optional &log;
	}; 
} 


### parse body
function parse_body(data: string)  : UMessage
{   
	local msg: UMessage;

	local array = split(data, /tfUPass=/);

	for( i in array)
   	{ 
		local val = array[i];
		msg$text = val;
   	} 
	
	if (i == 2)
	{
		return msg;
	}
	else
	{
		msg$text="";
		return msg;
	}


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
 	threshold = 2;

	http_body = data; 
	## GET SQL IN REQUEST BODY

	msg = parse_body(http_body);

	if(|msg$text| > 10)
		++ascore;
	

	if(match_sql_body in unescape_URI(msg$text))
		++ascore;

	if(match_sql_body2 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body3 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body4 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body5 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body6 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body7 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body8 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body9 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body10 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body11 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body12 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body13 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body14 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body15 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_body_numbers in unescape_URI(msg$text))
		++ascore;
	if(match_sql_injection_uri1 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_injection_uri2 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_injection_uri3 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_injection_uri4 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_injection_uri5 in unescape_URI(msg$text))
		++ascore;
	if(match_sql_injection_uri6 in unescape_URI(msg$text))
		++ascore;


	if ( ascore >= threshold)
	{ 

		NOTICE([$note=SQL_Post_Injection_Attack,
		$conn=c,
		$msg=fmt("SQL Attack from %s to destination: %s with Attack string %s\n\n", c$id$orig_h, c$id$resp_h, unescape_URI(msg$text))]);
	} 
	
} 


event http_request(c: connection, method: string, original_URI: string,
unescaped_URI: string, version: string) &priority=3
{ 

	local msg:UMessage;
	local body:UMessage;

	ascore = 1;
	threshold = 2;

	# GET SQL IN HTTP REQUEST HEADER

	msg = parse_uri(c$http$uri);

	# Test for string length
	if ( |msg$text| > 2)    
		++ascore;            

	if(match_sql_injection_uri1 in unescaped_URI)
		++ascore;

	if(match_sql_injection_uri2 in unescaped_URI)
		++ascore;
	if(match_sql_injection_uri3 in unescaped_URI)
		++ascore;
	if(match_sql_injection_uri4 in unescaped_URI)
		++ascore;
	if(match_sql_injection_uri5 in unescaped_URI)
		++ascore;
	if(match_sql_injection_uri6 in unescaped_URI)
		++ascore;
	if(match_sql_body2 in unescaped_URI)
		++ascore;
	if(match_sql_body3 in unescaped_URI)
		++ascore;
	if(match_sql_body4 in unescaped_URI)
		++ascore;
	if(match_sql_body5 in unescaped_URI)
		++ascore;
	if(match_sql_body6 in unescaped_URI)
		++ascore;
	if(match_sql_body7 in unescaped_URI)
		++ascore;
	if(match_sql_body8 in unescaped_URI)
		++ascore;
	if(match_sql_body9 in unescaped_URI)
		++ascore;
	if(match_sql_body10 in unescaped_URI)
		++ascore;
	if(match_sql_body11 in unescaped_URI)
		++ascore;
	if(match_sql_body12 in unescaped_URI)
		++ascore;
	if(match_sql_body13 in unescaped_URI)
		++ascore;
	if(match_sql_body14 in unescaped_URI)
		++ascore;
	if(match_sql_body15 in unescaped_URI)
		++ascore;
	if(match_sql_body_numbers in unescaped_URI)
		++ascore;


	if ( ascore >= threshold)
	{
		NOTICE([$note=SQL_URI_Injection_Attack,
		$conn=c,
		$msg=fmt("SQL Attack from %s to destination: %s with Attack string %s\n\n", c$id$orig_h, c$id$resp_h, unescape_URI(c$http$uri))]);
	}
}



