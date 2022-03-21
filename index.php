<?php
/**
 * Serialize: Generate cryptojs compatiable encoding token
 *
 * @param mixed $arg
 * @param mixed $key
 * @return string
 */
function TokenEncypt( $arg, $key ){

  $salt = openssl_random_pseudo_bytes(8);
  $salted = '';
  $dx = '';

  while( strlen( $salted ) < 48 ){
    $dx = md5( $dx . $key . $salt, true );
    $salted .= $dx;
  }

  $key = substr( $salted, 0, 32 );
  $iv  = substr( $salted, 32, 16 );
  $encrypted_data = openssl_encrypt( json_encode( $arg ), 'aes-256-cbc', $key, true, $iv );
  $cdata = json_encode([
                        'ct' => base64_encode( $encrypted_data ),
                        'iv' => bin2hex( $iv ),
                        's' => bin2hex( $salt )
                      ]);

  $randtoken = bin2hex( openssl_random_pseudo_bytes(4) ); // Generate a hexadecimal random string
  $encoded = base64_encode( $randtoken . $cdata );
  $index = (int)( strlen( $cdata ) / 2 ) - 1;

  return substr( $encoded, 0, $index ) .'xueWOeE9nPRXKzP3Rz'. substr( $encoded, $index );
}

/**
 * Unserialize: Extract data from a CryptoJS encoding string
 *
 * @param string $str
 * @param string $key
 * @return object
 */
function TokenDecrypt( $str, $key ){

  // Corruption line
  $str = base64_decode( str_replace( 'xueWOeE9nPRXKzP3Rz', '', $str ) );
  $str = str_replace( substr( $str, 0, 8 ), '', $str );

  $jsondata = json_decode( $str, true );
  if( !$jsondata ) return false;
  
  $salt = hex2bin( $jsondata['s'] );
  $ct = base64_decode( $jsondata['ct'] );
  $iv  = hex2bin( $jsondata['iv'] );

  $concatedPassphrase = $key . $salt;
  $md5 = array();
  $md5[0] = md5( $concatedPassphrase, true );
  $result = $md5[0];

  for( $i = 1; $i < 3; $i++ ){
    $md5[$i] = md5( $md5[ $i - 1 ] . $concatedPassphrase, true );
    $result .= $md5[$i];
  }

  $key = substr( $result, 0, 32 );
  $data = openssl_decrypt( $ct, 'aes-256-cbc', $key, true, $iv );

  return json_decode( $data, true );
}


// $encryptedJS = '{"ct":"9gV9SgrALe9H2hQh2dwk6rG1+4oj65DVCrKutci7LbQ=","iv":"9a7527615d78e63e4a09ed13aa3fec82","s":"4f122fbbd2c66d6d"}';
$encryptedJS = 'YWJjZDEyMzR7ImN0IjoiVUVmSEdYWXBBOEVCMk1OaEtZMmZxbS9VYXZjNXlRUxueWOeE9nPRXKzP3RzHYzUjJZU21kTjNlVT0iLCJpdiI6ImI4YjczNzE4Nzc1YjQyNTMwM2QzYWY3NTI5NWFhYzQxIiwicyI6IjRmMDUxYjQ3NWIwMGQ2YWMifQ==';
$key = "K5aSpkQr6gR2M0ZDlkOTc1NjQyN2M1NGUyN2NjZTg";
$decryptedPHP = TokenDecrypt( $encryptedJS, $key );

echo $decryptedPHP .'<br>';

$value = 'I like observing every miles of my life';
$encryptedPHP = TokenEncypt( $value, $key );

?>

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
  <title>PHP <-> JS | Crypto </title>
</head>
<body>
  <script type="text/javascript" src="crypto-js.js"></script>
  <script type="text/javascript">
    const
    encryptedPHP = '<?php echo $encryptedPHP; ?>',
    key = '<?php echo $key; ?>',
    CryptoJSAesJson = {

      stringify: cipherParams => {

        const obj = { ct: cipherParams.ciphertext.toString( CryptoJS.enc.Base64 ) }

        if( cipherParams.iv ) obj.iv = cipherParams.iv.toString()
        if( cipherParams.salt ) obj.s = cipherParams.salt.toString()

        return JSON.stringify( obj )
      },
      parse: jsonStr => {

        const
        obj = JSON.parse( jsonStr ),
        cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse( obj.ct ) })

        if( obj.iv ) cipherParams.iv = CryptoJS.enc.Hex.parse( obj.iv )
        if( obj.s ) cipherParams.salt = CryptoJS.enc.Hex.parse( obj.s )

        return cipherParams
      }
    },
    payload = 'Value to encrypt'

    function TokenEncypt( arg, key ){

      const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
      let
      str = CryptoJS.AES.encrypt( JSON.stringify( arg ), key, { format: CryptoJSAesJson } ).toString(),
      result = '',
      i = 0

      // Add random string or 8 length here
      str = 'abcd1234'+ str

      do {
          var a = str.charCodeAt(i++)
          var b = str.charCodeAt(i++)
          var c = str.charCodeAt(i++)

          a = a ? a : 0
          b = b ? b : 0
          c = c ? c : 0

          var b1 = ( a >> 2 ) & 0x3F
          var b2 = ( ( a & 0x3 ) << 4 ) | ( ( b >> 4 ) & 0xF )
          var b3 = ( ( b & 0xF ) << 2 ) | ( ( c >> 6 ) & 0x3 )
          var b4 = c & 0x3F

          if( !b ) b3 = b4 = 64
          else if( !c ) b4 = 64

          result += b64.charAt( b1 ) + b64.charAt( b2 ) + b64.charAt( b3 ) + b64.charAt( b4 )

      } while ( i < str.length )

      /* Corrupt encoded string to avoid universal
        base64 encoder functions to decode it

        Introduce unknown portion of string
      */
      let spliceIndex = parseInt( ( str.length / 2 ) - 1 )
      return result.slice( 0, spliceIndex ) +'xueWOeE9nPRXKzP3Rz'+ result.slice( spliceIndex )
    }

    function TokenDecrypt( str, key ){
      // Default Reverse Encrypting Tool: Modified Base64 decoder

      const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
      let result = '', i = 0

      // Remove the unknown striing portion
      str = str.replace('xueWOeE9nPRXKzP3Rz', '')

      do {
          var b1 = b64.indexOf( str.charAt(i++) )
          var b2 = b64.indexOf( str.charAt(i++) )
          var b3 = b64.indexOf( str.charAt(i++) )
          var b4 = b64.indexOf( str.charAt(i++) )

          var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 )
          var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF )
          var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F )

          result += String.fromCharCode( a ) + ( b ? String.fromCharCode( b ) : '' ) + ( c ? String.fromCharCode( c ) : '' )

      } while( i < str.length )

      result = result.replace( result.slice( 0, 8 ), '')

      return JSON.parse( CryptoJS.AES.decrypt( result, key, { format: CryptoJSAesJson }).toString( CryptoJS.enc.Utf8 ) )
    }

    const encryptedJS = TokenEncypt( payload, key )

    console.log('encryptedJS:', encryptedJS )
    console.log('decryptedJS: ', TokenDecrypt( encryptedJS, key ) )
    console.log('decryptedPHP: ', TokenDecrypt( encryptedPHP, key ) )
  </script>
</body>
</html>
