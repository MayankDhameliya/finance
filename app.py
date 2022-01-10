import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # userid of currently loged in user
    userId = session["user_id"]
 
    # user data about cash cand portfolio of share
    user_data = db.execute("SELECT * FROM users WHERE id = ?", userId)
    portfolio = db.execute("SELECT stock_list, shares FROM stock WHERE stock_id = ?", userId)

    cash = user_data[0]["cash"]

    # value of all shares holding
    all_stock_value_total = 0

    # finding current price of each stock
    for stock in portfolio:
        stock_symbol = stock["stock_list"]
        stock_detail = lookup(stock_symbol)

        # adding dict stock_detail to a perticulr stock in portfolio
        stock.update(stock_detail)

        total_value_of_specific_stock = stock_detail["price"] * stock["shares"]

        # adding 'total' key to individual stock to pass the value to index.html
        stock["total"] = total_value_of_specific_stock

        all_stock_value_total = all_stock_value_total + total_value_of_specific_stock

    total_balance = cash + all_stock_value_total

    # passing list portflolio, total cash left and final total of shares holding and cash
    return render_template("index.html", portfolio=portfolio, cash=cash, total_balance=total_balance)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # checking for empty fileds of symbol and quantity of shares
        if not symbol:
            return apology("must provide symbol", 400)
        if not shares or int(shares) < 1:
            return apology("must provide valid number of shares", 400)

        # verifing valid symbol
        stock = lookup(symbol)
        if stock == None:
            return apology("must provide valide stock name (eg. for Alpple Inc. - APPL)", 400)

        # user_id of currrenty loged in user
        userId = session["user_id"]
        user_data = db.execute("SELECT * FROM users WHERE id = ?", userId)

        total_purchas = stock["price"] * int(shares)
        AC_balance = user_data[0]["cash"]

        # verifing enough cash to make transation
        if total_purchas > AC_balance:
            return apology("not enoght cash", 400)

        # updating cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", AC_balance - total_purchas, userId)

        # finding current time and date to add transation into history table
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

        # adding data into history table
        db.execute("INSERT INTO history (history_id, stock_symbol, shares, time, price) VALUES (?, ?, ?, ?, ?)",
            user_data[0]["id"], stock["symbol"], shares, dt_string, stock["price"])

        stock_data = db.execute("SELECT stock_list, shares FROM stock WHERE stock_id = ?", userId)

        # adding stock to portfolio
        # if symbol is old, updating shares quantity
        for element in stock_data:
            if stock["symbol"] in element.values():
                db.execute("UPDATE stock SET shares = shares + ? WHERE stock_id = ? AND stock_list = ?",
                    shares, userId, stock["symbol"])
                return redirect("/")

        # else adding new symbol into portfolio
        db.execute("INSERT INTO stock (stock_id, stock_list, shares) VALUES (?, ?, ?)",
            user_data[0]["id"], stock["symbol"], shares)

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    userId = session["user_id"]

    history_table = db.execute("SELECT * FROM history WHERE history_id = ?", userId)

    return render_template("history.html", history_table=history_table)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")

        # checking price of entered stock
        stock = lookup(symbol)

        # error if retured value from llokup is none
        if stock == None:
            return apology("must provide valide stock name (eg. for Alpple Inc. - APPL)", 400)

        # passing stock data to quoted html
        return render_template("quoted.html", stock=stock)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":

        # three values that user enterd into the form
        user_name = request.form.get("username")
        password = request.form.get("password")
        re_password = request.form.get("confirmation")

        # varifing every input for valid input
        if not user_name:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)
        if not re_password:
            return apology("must conform password", 400)
        if re_password != password:
            return apology("different conform password", 400)

        # checking database for same username
        count = db.execute("SELECT * FROM users WHERE username = ?", user_name)

        # if length of count is not zero then username alreday exist and give error msg
        if len(count) > 0:
            return apology("Username already exist", 400)

        # finding hash value for entered user name
        hash_value = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # adding new user to database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", user_name, hash_value)

        return redirect("login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    userId = session["user_id"]
    if request.method == "GET":

        # getting all stock user owe from database
        stock_list = db.execute("SELECT stock_list FROM stock WHERE stock_id = ?", userId)

        return render_template("sell.html", stock_list=stock_list)

    if request.method == "POST":
        shares = request.form.get("shares")
        symbol = request.form.get("symbol")

        if not shares:
            return apology("must provide number of shares", 403)

        user_stock_data = db.execute("SELECT * FROM stock WHERE stock_id = ? AND stock_list = ?", userId, symbol)
        if int(shares) > int(user_stock_data[0]["shares"]):
            return apology("not have enogth shares to sell", 400)

        stock = lookup(symbol)

        # updating cash in database
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", stock["price"] * int(shares), userId)

        # deleting row if user selling all the stock else updating row
        if int(shares) == int(user_stock_data[0]["shares"]):
            db.execute("DELETE FROM stock WHERE stock_list = ? AND stock_id = ?", stock["symbol"], userId)
        else:
            db.execute("UPDATE stock SET shares = shares - ? WHERE stock_list = ? AND stock_id = ?",
                    shares, stock["symbol"], userId)

        # addign transation into history
        now = datetime.now()
        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        db.execute("INSERT INTO history (history_id, stock_symbol, shares, time, price) VALUES (?, ?, ?, ?, ?)",
            userId, stock["symbol"], "-" + shares, dt_string, stock["price"])

        return redirect("/")

@app.route("/changePassword", methods = ["GET", "POST"])
@login_required
def changePassword():
    """password change"""

    if request.method == "POST":

        userId = session["user_id"]

        oldPassword = request.form.get("oldPassword")
        newPassword = request.form.get("newPassword")
        conformPassword = request.form.get("confirmation")

        if not oldPassword:
            return apology("must provide oldPassword", 400)
        if not newPassword:
            return apology("must provide new password", 400)
        if not conformPassword:
            return apology("must conform password", 400)
        if conformPassword != newPassword:
            return apology("different conform password", 400)

        rows = db.execute("SELECT * FROM users WHERE id = ?", userId)

        if not check_password_hash(rows[0]["hash"], oldPassword):
            return apology("invalid old password", 403)

        hash_value = generate_password_hash(newPassword, method='pbkdf2:sha256', salt_length=8)

        # update hash value
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash_value, userId)

        return redirect("/")

    if request.method == "GET":
        return render_template("changePassword.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)