from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import requests
import json
import base64
import bcrypt
from html import escape

app = Flask(__name__)
# 앱의 시크릿 키 설정. 시크릿 키는 환경 변수에서 가져오거나 기본값으로 설정됩니다.
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')

# 데이터베이스 파일 경로 설정
DATABASE = 'database.db'

# 세션 쿠키를 안전하게 설정합니다.
app.config['SESSION_COOKIE_SECURE'] = True

# 현재 선택된 제품 정보를 저장하는 전역 변수
Product = ""
# 현재 로그인한 사용자의 이름을 저장하는 전역 변수
UserName = ""

# 데이터베이스 연결을 얻는 함수
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# 관리자인지 확인하는 함수
def is_admin():
    return 'admin_logged_in' in session

# 메인 페이지
@app.route('/')
def index():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, name, price, image FROM products')
    products = cur.fetchall()
    conn.close()
    return render_template('index.html', products=products)

# 주문 페이지
@app.route('/order')
def order():
    return render_template('order.html')

# 결제 페이지
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    # 주문 정보를 얻어옴
    product_id = request.form['product_id']
    product_name = request.form['product_name']
    name = request.form['name']
    phoneNumber = request.form['phoneNumber']
    email = request.form['email']
    amount = request.form['amount']
    userId = request.form['userId']
    address = request.form['address']

    # 결제할 제품 정보를 생성
    product = {
        'id': "product_id",
        'name': "product_name",
        'amount': amount
    }

    # 결제 페이지 렌더링
    return render_template('payment.html', product=product, product_id=product_id, product_name=product_name, name=name, phoneNumber=phoneNumber, email=email, amount=amount, userId=userId, address=address)

# 결제 성공 페이지
@app.route('/success')
def success():
    # Toss Payments에서 전달된 쿼리 파라미터 추출
    payment_key = request.args.get('paymentKey', "")
    order_id = request.args.get('orderId', "")
    amount = request.args.get('amount', "")
    
    # Toss Payments의 시크릿 키
    secret_key = '#여러분의 시크릿 키#'

    # Toss Payments API를 사용하여 결제 완료 처리
    url = f"https://api.tosspayments.com/v1/payments/{payment_key}" 
    headers = {'Authorization': f'Basic {base64.b64encode(secret_key.encode()).decode()}', 'Content-Type': 'application/json'}
    payload = {'orderId': order_id, 'amount': amount}
    response = requests.post(url, data=json.dumps(payload), headers=headers)

    # 결제 결과 출력
    print("----------------------------------------------------")
    print(f"status = {response}")
    print("----------------------------------------------------")

    # 결제 성공 페이지 렌더링
    return render_template('success.html', result=escape(response.json()))

# 결제 취소 페이지
@app.route('/cancel')
def cancel():
    return "결제가 취소되었습니다."

# 체크아웃 페이지
@app.route('/checkout')
def checkout():
    # 체크아웃 정보를 얻어옴
    product_id = Product['id']
    product_name = Product['name']
    amount = int(Product['price'])
    name = request.args.get('name')
    phoneNumber = request.args.get('phoneNumber')
    email = request.args.get('email')
    userId = UserName
    address = request.args.get('address')

    # 체크아웃 페이지 렌더링
    return render_template('checkout.html', product_id=product_id, product_name=product_name, name=name, phoneNumber=phoneNumber, email=email, amount=amount, userId=userId, address=address)

# 제품 구매 페이지
@app.route('/purchase/<int:product_id>', methods=['GET', 'POST'])
def purchase(product_id):
    # 로그인되어 있지 않으면 로그인 페이지로 리다이렉트
    if 'username' not in session:
        flash('로그인이 필요합니다.', 'error')
        return redirect(url_for('login'))

    global Product

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM products WHERE id=?', (product_id,))
    Product = cur.fetchone()

    return render_template("purchase.html", product=Product)

# 회원가입 페이지
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        address = request.form['address']
        payment_info = request.form['payment_info']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, password, address, payment_info) VALUES (?, ?, ?, ?)',
                    (username, hashed_password, address, payment_info))
        conn.commit()
        conn.close()
        flash('회원가입이 완료되었습니다. 로그인해주세요.', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

# 로그인 페이지
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        user = cur.fetchone()
        conn.close()
        
        global UserName
        UserName = user['username']

        if user:
            session['username'] = user['username']
            session['user_id'] = user['id']
            flash('로그인되었습니다.', 'success')
            return redirect(url_for('index'))
        else:
            flash('아이디 또는 비밀번호가 잘못되었습니다.', 'error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')

# 관리자 로그인 페이지
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        user = cur.fetchone()
        conn.close()

        if user:
            session['admin_logged_in'] = True
            flash('로그인 성공', 'success')
            return redirect(url_for('admin'))
        else:
            flash('아이디 또는 비밀번호가 잘못되었습니다.', 'error')

    return render_template('admin_login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

# 마이 페이지
@app.route('/my_page')
def my_page():
    if 'username' not in session:
        flash('로그인이 필요합니다.', 'error')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM purchases WHERE user_id=?', (session['user_id'],))
    purchases = cur.fetchall()
    conn.close()
    return render_template('my_page.html', purchases=purchases)

# 관리자 페이지
@app.route('/admin')
def admin():
    if not is_admin():
        flash('관리자 권한이 필요합니다.', 'error')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM purchases')
    purchases = cur.fetchall()
    conn.close()
    return render_template('admin.html', purchases=purchases)

# 제품 추가
@app.route('/add_product', methods=['POST'])
def add_product():
    if not is_admin():
        flash('관리자 권한이 필요합니다.', 'error')
        return redirect(url_for('admin_login'))

    name = request.form['name']
    price = request.form['price']
    image = request.form['image']
    category = request.form.get('category', '')

    # 가격은 정수형으로 변환하여 저장
    try:
        price = int(price)
    except ValueError:
        flash('가격은 정수값으로 입력해주세요.', 'error')
        return redirect(url_for('admin'))

    # 이미지 URL이 http:// 또는 https://로 시작하는지 확인
    if not image.startswith(('http://', 'https://')):
        flash('이미지 URL은 "http://" 또는 "https://"로 시작해야 합니다.', 'error')
        return redirect(url_for('admin'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO products (name, price, image, category) VALUES (?, ?, ?, ?)',
                (name, price, image, category))
    conn.commit()
    conn.close()

    flash('상품이 등록되었습니다.', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)