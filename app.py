import os
import re
import stripe

from flaskext.mysql import MySQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from hashlib import md5
from time import localtime
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# MySQL configuration
mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = 'starcrusher'
app.config['MYSQL_DATABASE_DB'] = 'eshop'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

cursor = mysql.connect().cursor()

app.config['UPLOAD_FOLDER'] = "./static/img/products/"
ALLOWED_EXTENSIONS = {'jpg', 'jpeg'}


@app.route("/")
def index():
    category = request.args.get("category")
    substring = request.args.get("substring")
    limit = request.args.get("limit")

    if not limit:
        limit = "25"

    cursor.execute("SELECT name FROM subcategories")
    options = cursor.fetchall()

    if category and not substring:
        cursor.execute(
            "SELECT * FROM users JOIN products ON users.user_id = products.seller_id JOIN subcategory_connector ON products.product_id = subcategory_connector.product_id JOIN subcategories ON subcategory_connector.subcategory_id = subcategories.subcategory_id WHERE subcategories.name = %s LIMIT %s", (category, int(limit)))
        data = cursor.fetchall()
    elif substring and not category:
        cursor.execute(
            f"SELECT * FROM users JOIN products ON users.user_id = products.seller_id WHERE products.title LIKE '%{substring}%' LIMIT {int(limit)}")
        data = cursor.fetchall()
    elif category and substring:
        cursor.execute(
            f"SELECT * FROM users JOIN products ON users.user_id = products.seller_id JOIN subcategory_connector ON products.product_id = subcategory_connector.product_id JOIN subcategories ON subcategory_connector.subcategory_id = subcategories.subcategory_id WHERE subcategories.name = '{category}' AND products.title LIKE '%{substring}%' LIMIT {int(limit)}")
        data = cursor.fetchall()
    else:
        cursor.execute(
            "SELECT * FROM users JOIN products ON users.user_id = products.seller_id LIMIT %s", (int(limit)))
        data = cursor.fetchall()

    if "user_id" in session:
        cursor.execute("SELECT username FROM users WHERE user_id = %s",
                       (session["user_id"]))
        username = cursor.fetchone()[0]
        if username:
            return render_template("index.html", data=data, username=username, options=options, category=category, substring=substring, limit=limit)
    else:
        return render_template("index.html", data=data, options=options, category=category, substring=substring, limit=limit)


@app.route("/details")
def details():
    item = request.args.get('item')

    cursor.execute(
        "SELECT * FROM products JOIN users ON products.seller_id = users.user_id WHERE product_id = %s", (item))
    data = cursor.fetchone()

    if not data:
        return apology("Error: this product doesn't exist!")
    cursor.execute(
        "SELECT name, category_id FROM subcategories JOIN subcategory_connector ON subcategories.subcategory_id = subcategory_connector.subcategory_id WHERE subcategory_connector.product_id = %s", (data[0]))
    subcategory = cursor.fetchone()

    if not subcategory:
        return render_template("details.html", data=data, subcategory="", category="")

    cursor.execute(
        "SELECT categories.name FROM categories JOIN subcategories ON subcategories.category_id = categories.category_id WHERE subcategory_id = %s", (subcategory[1]))
    category = cursor.fetchone()

    return render_template("details.html", data=data, subcategory=subcategory, category=category)


@app.route("/add-to-basket", methods=["GET", "POST"])
@login_required
def add_to_basket():
    item = request.args.get('item')
    amount = request.args.get('amount')

    cursor.execute(
        "SELECT * FROM basket WHERE user_id = %s AND product_id = %s", (session["user_id"], item))
    in_basket = cursor.fetchone()

    if in_basket:
        cursor.execute(
            "UPDATE basket SET amount = amount + %s", (amount))
        cursor.connection.commit()
    else:
        cursor.execute(
            "INSERT INTO basket (user_id, product_id, amount) VALUES (%s, %s, %s)", (session["user_id"], item, amount))
        cursor.connection.commit()

    if int(amount) == 1:
        flash("1 item added to basket.")
    elif int(amount) > 1:
        flash(f"{amount} items added to basket.")

    return redirect("/")


@app.route("/basket", methods=["GET", "POST"])
@login_required
def basket():
    if request.method == "GET":
        cursor.execute(
            "SELECT title, description, image, price, products.product_id, basket.amount FROM products JOIN basket ON products.product_id = basket.product_id WHERE basket.user_id = %s", (session["user_id"]))
        data = cursor.fetchall()
        cursor.execute(
            "SELECT balance FROM users WHERE user_id = %s", (session["user_id"]))
        user_balance = cursor.fetchone()

        cursor.execute(
            "SELECT email, phone, billing_address, shipping_address FROM users WHERE user_id = %s", (session["user_id"]))
        contact = cursor.fetchone()

        item_count = len(data)
        total_price = 0
        for row in data:
            total_price += int(row[3]) * int(row[5])

        return render_template("basket.html", data=data, item_count=item_count, total_price=total_price, user_balance=user_balance, contact=contact)
    else:
        item = request.form.get("item")
        user = session["user_id"]
        cursor.execute(
            "DELETE FROM basket WHERE user_id = %s AND product_id = %s", (user, item))
        cursor.connection.commit()
        flash("Item removed from basket.")
        return redirect("/basket")


@ app.route("/order", methods=["POST"])
@ login_required
def order():
    cursor.execute(
        "SELECT title, description, image, price, products.product_id, basket.amount FROM products JOIN basket ON products.product_id = basket.product_id WHERE basket.user_id = %s", (session["user_id"]))
    data = cursor.fetchall()
    total_cost = 0
    for row in data:
        total_cost += int(row[3]) * int(row[5])

    cursor.execute(
        "SELECT balance FROM users WHERE user_id = %s", (session["user_id"]))
    user_balance = cursor.fetchone()

    if total_cost <= user_balance[0]:
        cursor.execute("UPDATE users SET balance = balance - %s WHERE user_id = %s",
                       (total_cost, session["user_id"]))
        for row in data:
            cursor.execute("UPDATE products SET stock = stock - %s WHERE product_id = %s",
                           (row[5], row[4]))

        cursor.execute("DELETE FROM basket WHERE user_id = %s",
                       (session["user_id"]))
    flash(f"Order completed. ${total_cost} removed from your account.")
    return redirect("/")


@ app.route("/my-products", methods=["GET", "POST"])
@ login_required
def my_products():
    if request.method == "GET":
        cursor.execute(
            "SELECT title, description, image, price, product_id FROM products WHERE products.seller_id = %s", (session["user_id"]))
        data = cursor.fetchall()

        return render_template("my-products.html", data=data)
    else:
        item = request.form.get("item")
        if item:
            cursor.execute(
                "DELETE FROM basket WHERE product_id = %s", (item))
            cursor.execute(
                "DELETE FROM subcategory_connector WHERE product_id = %s", (item))
            cursor.execute(
                "DELETE FROM products WHERE product_id = %s", (item))
            cursor.connection.commit()

        cursor.execute(
            "SELECT title, description, image, price, product_id FROM products WHERE products.seller_id = %s", (session["user_id"]))
        data = cursor.fetchall()

        flash("Item deleted.")
        return render_template("my-products.html", data=data)


@ app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        first_name = request.form.get("first-name")
        last_name = request.form.get("last-name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm-password")
        phone = request.form.get("phone")
        email = request.form.get("email")
        country = request.form.get("country")

        # If no first name is provided, set it to None
        # else validate it
        if first_name:
            if len(first_name) > 32:
                return apology(
                    "Length of first name must not exceed 32 characters!")
        else:
            first_name = None

        # If no last name is provided, set it to None
        # else validate it
        if last_name:
            if len(last_name) > 32:
                return apology(
                    "Length of last name must not exceed 32 characters!")
        else:
            last_name = None

        # Validate username
        if username:
            if 6 <= len(username) <= 32:
                if not re.match(r"[0-9a-zA-Z]", username):
                    return apology(
                        "Username must only contain letters and numbers [a-z, A-Z, 0-9]!")
            else:
                return apology("Length of username must be between 6 and 32 characters.")
        else:
            return apology("Please provide a username.")

        # Validate and confirm password
        if password:
            if 6 <= len(password) <= 32:
                if not confirm_password:
                    return apology("You must confirm your password.")
                elif not confirm_password == password:
                    return apology("Passwords must match.")
            else:
                return apology("Length of password must be between 6 and 32 characters.")
        else:
            return apology("Please provide a password.")

        # Validate email
        if email:
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                return apology("Email address must be correct!")
            else:
                cursor.execute(
                    "SELECT user_id FROM users WHERE email = %s", email)
                data = cursor.fetchall()
                if not len(data) == 0:
                    return apology("This email address is already registered!")
        else:
            return apology("You must provide an email address!")

        # If no phone number is provided, set it to None
        # else validate it
        if not phone:
            phone = None
        else:
            if not re.match(r"[0-9]", phone):
                return apology("Phone number must only contain numbers!")
        # If no country is provided, set to None
        if not country:
            country = None

        cursor.execute("INSERT INTO users (first_name, last_name, username, password, email, phone, country) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                       (first_name, last_name, username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=8), email, phone, country))
        cursor.connection.commit()
        flash('You registered succesfully.')
        return redirect("/login")


@ app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "GET":
        return render_template("login.html")
    else:
        email = request.form.get("email")
        password = request.form.get("password")

        if not email:
            return apology("You must provide an email!")
        if not password:
            return apology("You must provide a password!")

        # Query database for user
        cursor.execute("SELECT * FROM users WHERE email = %s",
                       (email))
        data = cursor.fetchone()

        # Ensure user is registered and password is correct
        if not data:
            return apology("You are not yet registered!")
        elif not check_password_hash(data[4], password):
            return apology("Invalid email or password!")

        # Remember which user has logged in
        session["user_id"] = data[0]
        cursor.execute(
            "SELECT username FROM users WHERE user_id = %s", (session["user_id"]))
        username = cursor.fetchone()
        session["username"] = username[0]
        return redirect("/")


@ app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect("/")


@ app.route("/user", methods=["GET", "POST"])
@ login_required
def user():
    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE user_id = %s",
                       session["user_id"])
        data = cursor.fetchone()

        return render_template("user.html", data=data)


@ app.route("/change-password", methods=["GET", "POST"])
@ login_required
def change_password():
    if request.method == "GET":
        return render_template("change-password.html")
    else:
        password = request.form.get("password")
        confirm_password = request.form.get("confirm-password")

        # Validate and confirm password
        if password:
            if 6 <= len(password) <= 32:
                if not confirm_password:
                    return apology("You must confirm your password.")
                elif not confirm_password == password:
                    return apology("Passwords must match.")
            else:
                return apology("Length of password must be between 6 and 32 characters.")
        else:
            return apology("Please provide a password.")

        cursor.execute("UPDATE users SET password = %s WHERE user_id = %s", (generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=8), session["user_id"]))
        flash("Password changed.")
        return redirect("/user")


@ app.route("/change-product", methods=["GET", "POST"])
@ login_required
def change_product():
    if request.method == "GET":
        item = request.args.get("item")
        cursor.execute("SELECT title, description, subcategories.name, image, price, stock, products.product_id, subcategory_connector.subcategory_id FROM products JOIN subcategory_connector ON products.product_id = subcategory_connector.product_id JOIN subcategories ON subcategory_connector.subcategory_id = subcategories.subcategory_id WHERE products.product_id = %s", (item))
        data = cursor.fetchone()
        # return apology(data)

        return render_template("change-product.html", data=data)
    else:
        title = request.form.get("title")
        description = request.form.get("description")
        category = request.form.get("categories")
        image = request.files['image']
        price = request.form.get("price")
        stock = request.form.get("amount")
        product_id = request.form.get("id")
        # subcategory_id = request.form.get("subcategory-id")

        if image:
            image_hash_path = md5(str(localtime()).encode('utf-8')).hexdigest()
            image_path = f"../static/img/products/{image_hash_path}.jpg"
            image.save(os.path.join(
                app.config['UPLOAD_FOLDER'], f"{image_hash_path}.jpg"))

            cursor.execute(
                "UPDATE products SET title = %s, description = %s, image = %s, price = %s, stock = %s WHERE product_id = %s", (title, description, image_path, price, stock, product_id))
            cursor.connection.commit()
        else:
            cursor.execute(
                "UPDATE products SET title = %s, description = %s, price = %s, stock = %s WHERE product_id = %s", (title, description, price, stock, product_id))
            cursor.connection.commit()

        cursor.execute(
            f"SELECT subcategory_id FROM subcategories WHERE name = '{category}'")
        subcategory_id = cursor.fetchone()

        cursor.execute("UPDATE subcategory_connector SET subcategory_id = %s WHERE product_id = %s",
                       (subcategory_id, product_id))
        cursor.connection.commit()

        return redirect("/my-products")


@ app.route("/change-info", methods=["GET", "POST"])
@ login_required
def change_info():
    if request.method == "GET":
        cursor.execute(
            "SELECT phone, country, billing_address, shipping_address FROM users WHERE user_id = %s", (session["user_id"]))
        data = cursor.fetchone()
        return render_template("change-info.html", data=data)
    else:
        user = session["user_id"]
        phone = request.form.get("phone")
        country = request.form.get("country")
        billing_address = request.form.get("billing-address")
        shipping_address = request.form.get("shipping-address")

        if not billing_address:
            billing_address = None

        if not shipping_address:
            shipping_address = None

        cursor.execute(
            "UPDATE users SET phone = %s WHERE user_id = %s", (phone, user))
        cursor.execute(
            "UPDATE users SET country = %s WHERE user_id = %s", (country, user))
        cursor.execute(
            "UPDATE users SET billing_address = %s WHERE user_id = %s", (billing_address, user))
        cursor.execute(
            "UPDATE users SET shipping_address = %s WHERE user_id = %s", (shipping_address, user))
        cursor.connection.commit()
        return redirect("/user")


@ app.route("/add-product", methods=["GET", "POST"])
@ login_required
def add_product():
    if request.method == "GET":
        return render_template("add-product.html")
    else:
        title = request.form.get("title")
        description = request.form.get("description")
        image = request.files['image']
        categories = request.form.get("categories")
        price = request.form.get("price")
        amount = request.form.get("amount")
        uploader = session["user_id"]

        if not title:
            return apology("You must give your product a title!")
        elif not description:
            return apology("You must describe your product!")
        elif not image:
            return apology("You must provide an image for your product!")
        elif not categories:
            return apology("You must categorize your product, else nobody will find it!")
        elif not price:
            return apology("You must give a price to your product!")
        elif not amount:
            return apology("You must specify what amount of this product you can supply!")

        # Check for any unwanted words
        words = ["fuck", "dick", "cunt", "shit", "pussy", "piss",
                 "bitch", "bastard", "damn", "wanker", "retard", "idiot"]

        for word in words:
            if word in title.lower() or word in description.lower():
                return apology("Please keep in mind our No Swearing policy!")

        # Save image to server and remember it in database
        image_hash_path = md5(str(localtime()).encode('utf-8')).hexdigest()
        image_path = f"../static/img/products/{image_hash_path}.jpg"
        image.save(os.path.join(
            app.config['UPLOAD_FOLDER'], f"{image_hash_path}.jpg"))

        cursor.execute("INSERT INTO products (seller_id, title, description, image, price, stock) VALUES (%s, %s, %s, %s, %s, %s)",
                       (uploader, title, description, image_path, price, amount))
        cursor.connection.commit()

        cursor.execute(
            "SELECT product_id FROM products WHERE title = %s AND seller_id = %s LIMIT 1", (title, uploader))
        product_id = cursor.fetchone()

        cursor.execute(
            "SELECT subcategory_id FROM subcategories WHERE name = %s", (categories))
        subcategory_id = cursor.fetchone()

        if product_id and subcategory_id:
            cursor.execute("INSERT INTO subcategory_connector (product_id, subcategory_id) VALUES (%s, %s)",
                           (product_id, subcategory_id))
            cursor.connection.commit()

        flash("Product added.")
        return redirect("/")


def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
