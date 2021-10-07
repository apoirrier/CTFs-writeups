# Most Cookies

> Alright, enough of using my own encryption. Flask session cookies should be plenty secure!
>
> http://mercury.picoctf.net:53700/

The server code is also included:

```python
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()
```

## Description

By going to the webpage, we see that we can enter some value.
This changes the session cookie, and if we enter the proposed choice `snickerdoodle`, we get a page saying `Hello snickerdoodle`, but stating this is a regular cookie.

By inputting the cookie on CyberChef, I see this is the base64 encoding of `{"very_auth": "snickerdoodle"}` along with some sort of signature on it.

By reading the source code, I see that I can get the flag if I manage to get the value of `very_auth` to `admin`.

However the signature prevents me from doing it directly.

Thankfully, I see the line on the server code `app.secret_key = random.choice(cookie_names)`, which means the signature is performed using one of those private keys.

As it only has roughly 30 different values, I can bruteforce the key value easily.

## Solution

I have used [flask-unsign](https://pypi.org/project/flask-unsign/) to brute force the key and sign my new cookie.

First to brute force the key, I extract each possible value in a text file named `keys.txt`.

Then I run this command:

```bash
flask-unsign -u -c eyJ2ZXJ5X2F1dGgiOiJzbmlja2VyZG9vZGxlIn0.YV8OLw.dIhVhH8cI6zLjzpW5GDWAIKoipM -w keys.txt
```

with the value of the cookie I have found by inputting `snickerdoodle`.

This tells me the key is `peanut butter`.

Then I craft my own cookie:

```bash
flask-unsign --sign --cookie "{'very_auth': 'admin'}" --
secret 'peanut butter'
```

I input the value on the website and I get back the flag.

Flag: `picoCTF{pwn_4ll_th3_cook1E5_3646b931}`