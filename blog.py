from flask import Flask, render_template, flash, redirect, url_for, session, request, jsonify
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import os
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'static/uploads'  # Fotoğrafların kaydedileceği klasör

# Flask Config
app.secret_key = "ybblog"  # Secret key
app.config['WTF_CSRF_ENABLED'] = True  # CSRF koruması etkin
app.config['WTF_CSRF_SECRET_KEY'] = 'your-secret-key'  # CSRF Secret Key
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "ybblog"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Yalnızca bu dosya türlerine izin ver

# MySQL bağlantısı
mysql = MySQL(app)

# CSRF koruması
csrf = CSRFProtect(app)

# Dosya türünün izin verilen türlerden biri olup olmadığını kontrol eden yardımcı fonksiyon
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Kullanıcı Giriş Decorator'ı
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntülemek için lütfen giriş yapın.", "danger")
            return redirect(url_for("login"))
    return decorated_function

# Kullanıcı kayıt formu
class RegisterForm(FlaskForm):
    name = StringField("İsim Soyisim", validators=[validators.Length(min=4, max=25)])
    username = StringField("Kullanıcı Adı", validators=[validators.Length(min=5, max=35)])
    email = StringField("Email", validators=[validators.Email(message="Lütfen geçerli bir email girin...")])
    password = PasswordField("Parola:", validators=[
        validators.DataRequired(message="Lütfen bir parola belirleyin"),
        validators.EqualTo(fieldname="confirm", message="Parolanız uyuşmuyor...")
    ])
    confirm = PasswordField("Parola Doğrula")

# Kullanıcı giriş formu
class LoginForm(FlaskForm):
    username = StringField("Kullanıcı Adı")
    password = PasswordField("Parola")

# Makale formu
class ArticleForm(FlaskForm):
    title = StringField("Makale Başlığı", validators=[validators.Length(min=5, max=100)])
    content = TextAreaField("Makale İçeriği", validators=[validators.Length(min=10)])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/articles")
def articles():
    cursor = mysql.connection.cursor()
    query = "SELECT * FROM articles"
    result = cursor.execute(query)
    if result > 0:
        articles = cursor.fetchall()
        return render_template("articles.html", articles=articles)
    else:
        return render_template("articles.html")

@app.route("/dashboard")
@login_required
def dashboard():
    cursor = mysql.connection.cursor()
    query = "SELECT * FROM users WHERE username = %s"
    result = cursor.execute(query, (session["username"],))
    if result > 0:
        user = cursor.fetchone()  # Kullanıcı bilgilerini al
        return render_template("dashboard.html", user=user)
    else:
        return render_template("dashboard.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        cursor = mysql.connection.cursor()
        query = "INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)"
        cursor.execute(query, (name, email, username, password))
        mysql.connection.commit()
        cursor.close()

        flash("Başarıyla Kayıt Oldunuz...", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST":
        username = form.username.data
        password_entered = form.password.data

        cursor = mysql.connection.cursor()
        query = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(query, (username,))

        if result > 0:
            data = cursor.fetchone()
            real_password = data["password"]
            if sha256_crypt.verify(password_entered, real_password):
                flash("Başarıyla Giriş Yaptınız...", "success")
                session["logged_in"] = True
                session["username"] = username
                session["name"] = data["name"]
                session["email"] = data["email"]
                return redirect(url_for("index"))
            else:
                flash("Parolanızı Yanlış Girdiniz...", "danger")
                return redirect(url_for("login"))
        else:
            flash("Böyle bir kullanıcı bulunmuyor...", "danger")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/article/<string:id>")
def article(id):
    cursor = mysql.connection.cursor()
    query = "SELECT * FROM articles WHERE id = %s"
    result = cursor.execute(query, (id,))
    if result > 0:
        article = cursor.fetchone()
        return render_template("article.html", article=article)
    else:
        return render_template("article.html")

#MAKALE EKLEME
@app.route("/addarticle", methods=["GET", "POST"])
@login_required
def addarticle():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        content = form.content.data

        cursor = mysql.connection.cursor()
        query = "INSERT INTO articles (title, author, content) VALUES (%s, %s, %s)"
        cursor.execute(query, (title, session["username"], content))
        mysql.connection.commit()
        cursor.close()

        flash("Makale başarıyla eklendi.", "success")
        return redirect(url_for("dashboard"))
    return render_template("addarticle.html", form=form)

#MAKALE SİLME
@app.route("/delete/<string:id>")
@login_required
def delete(id):
    cursor = mysql.connection.cursor()
    query = "SELECT * FROM articles WHERE author = %s AND id = %s"
    result = cursor.execute(query, (session["username"], id))
    if result > 0:
        query2 = "DELETE FROM articles WHERE id = %s"
        cursor.execute(query2, (id,))
        mysql.connection.commit()
        return redirect(url_for("dashboard"))
    else:
        flash("Böyle bir makale yok veya bu işleme yetkiniz yok", "danger")
        return redirect(url_for("index"))

#MAKALE DÜZENLEME
@app.route("/edit/<string:id>", methods=["GET", "POST"])
@login_required
def update(id):
    if request.method == "GET":
        cursor = mysql.connection.cursor()
        query = "SELECT * FROM articles WHERE id = %s AND author = %s"
        result = cursor.execute(query, (id, session["username"]))
        if result == 0:
            flash("Böyle bir makale yok veya bu işleme yetkiniz yok.", "danger")
            return redirect(url_for("index"))
        else:
            article = cursor.fetchone()
            form = ArticleForm()
            form.title.data = article["title"]
            form.content.data = article["content"]
            return render_template("update.html", form=form)
    else:
        form = ArticleForm(request.form)
        new_title = form.title.data
        new_content = form.content.data

        query = "UPDATE articles SET title = %s, content = %s WHERE id = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(query, (new_title, new_content, id))
        mysql.connection.commit()

        flash("Makale başarıyla güncellendi", "success")
        return redirect(url_for("dashboard"))

@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "GET":
        return redirect(url_for("index"))
    else:
        keyword = request.form.get("keyword")
        cursor = mysql.connection.cursor()
        query = "SELECT * FROM articles WHERE title LIKE %s"
        result = cursor.execute(query, ('%' + keyword + '%',))
        if result == 0:
            flash("Aranan kelimeye uygun makale bulunamadı", "warning")
            return redirect(url_for("index"))
        else:
            articles = cursor.fetchall()
            return render_template("articles.html", articles=articles)

#Koyu tema için
@app.route('/set-theme', methods=['POST'])
def set_theme():
    data = request.get_json()
    session['theme'] = data['theme']
    return '', 204        

#Makalelerim
@app.route("/my_articles")
@login_required  # Kullanıcının giriş yapmış olduğundan emin olun
def my_articles():
    cursor = mysql.connection.cursor()

    # Kullanıcının yalnızca kendi makalelerini getirecek sorgu
    sorgu = "SELECT * FROM articles WHERE author = %s"
    result = cursor.execute(sorgu, (session["username"],))

    if result > 0:
        articles = cursor.fetchall()  # Makaleleri al
        return render_template("my_articles.html", articles=articles)
    else:
        return render_template("my_articles.html", message="Henüz makaleniz bulunmuyor.")

#Profil Güncelleme
@app.route("/editprofile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data

        # Fotoğraf dosyasını kontrol etme
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

                try:
                    file.save(file_path)
                    flash("Profil fotoğrafınız başarıyla yüklendi.", "success")
                except Exception as e:
                    flash(f"Fotoğraf yüklenirken hata oluştu: {e}", "danger")
                    return render_template("editprofile.html", form=form)

                # Veritabanına dosya adını kaydetme
                cursor = mysql.connection.cursor()
                cursor.execute("UPDATE users SET name = %s, email = %s, profile_picture = %s WHERE username = %s",
                               (name, email, filename, session["username"]))
                mysql.connection.commit()
                cursor.close()
            else:
                flash("Geçersiz dosya türü veya dosya yüklenmedi. Lütfen yalnızca resim dosyaları yükleyin.", "warning")
        else:
            # Fotoğraf yüklenmemişse sadece adı ve e-posta adresini güncelle
            cursor = mysql.connection.cursor()
            cursor.execute("UPDATE users SET name = %s, email = %s WHERE username = %s",
                           (name, email, session["username"]))
            mysql.connection.commit()
            cursor.close()

        flash("Profiliniz başarıyla güncellendi.", "success")
        return redirect(url_for("dashboard"))

    else:
        # Kullanıcı verilerini al ve formu doldur
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (session["username"],))
        user = cursor.fetchone()
        if user:
            form.name.data = user["name"]
            form.email.data = user["email"]

    return render_template("editprofile.html", form=form)

if __name__ == "__main__":
    app.run(debug=True)

