from flask import Flask, render_template, request, redirect, url_for, Response, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import csv
from io import StringIO
from datetime import datetime
import os
import uuid
import re
import logging
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter                   # NEW: Import Limiter
from flask_limiter.util import get_remote_address   # NEW: Import IP tracking utility
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv()

# --- FLASK CONFIGURATION ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_production_key')

# Check if we are in local development or live production
is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']

# Lock down session cookies
app.config.update(
    SESSION_COOKIE_SECURE=not is_debug,  # Requires HTTPS in production, allows HTTP locally
    SESSION_COOKIE_HTTPONLY=True,        # Prevents JavaScript from reading the cookie
    SESSION_COOKIE_SAMESITE='Lax'        # Protects against cross-site request forgery
)

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per 15 seconds"],
    storage_uri="memory://"
)

firebase_cert_path = os.environ.get("FIREBASE_CREDENTIALS", "firebase_credentials.json")
try:
    cred = credentials.Certificate(firebase_cert_path)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)
    db = firestore.client()
except FileNotFoundError:
    logging.critical(f"Firebase credentials not found at {firebase_cert_path}. App cannot start.")
    raise
# -------------------------------

CURRENCIES = {
    "USD": "$", "EUR": "€", "GBP": "£", "INR": "₹", "JPY": "¥",
    "AUD": "A$", "CAD": "C$", "CHF": "CHF", "CNY": "¥"
}

@app.errorhandler(429)
def ratelimit_handler(e):
    # If a user clicks too fast, flash a warning and send them back safely
    flash(f"Whoa, slow down! {e.description}")
    return redirect(request.referrer or url_for('index'))

def sanitize_key(key_string):
    """Strips dangerous/special characters from strings used as dictionary keys."""
    return re.sub(r'[^a-zA-Z0-9 _-]', '', str(key_string)).strip()

def get_user_data(username):
    try:
        doc = db.collection('users').document(username).get()
        if not doc.exists:
            return None
            
        user_data = doc.to_dict()
        needs_update = False
        
        defaults = {
            "currency": "USD", "budgets": {}, "transactions": [],
            "subscriptions": [], "savings_goals": {}, "debts": {},
            "last_billed_month": ""
        }
        
        for key, default_val in defaults.items():
            if key not in user_data:
                user_data[key] = default_val
                needs_update = True
                
        for t in user_data['transactions']:
            if 'id' not in t:
                t['id'] = str(uuid.uuid4())
                needs_update = True
                
        if needs_update:
            save_user_data(username, user_data)
            
        return user_data
    except Exception as e:
        logging.error(f"Database error fetching user {username}: {e}")
        return None

def save_user_data(username, data):
    try:
        db.collection('users').document(username).set(data)
    except Exception as e:
        logging.error(f"Failed to save data for user {username}: {e}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per 15 seconds")
def register():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        if get_user_data(username):
            flash("Username already exists!")
            return redirect(url_for('register'))
            
        new_user = {
            "password_hash": generate_password_hash(password),
            "currency": "USD", "budgets": {}, "transactions": [],
            "subscriptions": [], "savings_goals": {}, "debts": {},
            "last_billed_month": "" # NEW: For the Auto-Biller
        }
        save_user_data(username, new_user)
        session['username'] = username
        return redirect(url_for('index'))
    return render_template('auth.html', action="Register")

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 15 seconds")
def login():
    if request.method == 'POST':
        username = request.form['username'].lower()
        password = request.form['password']
        user = get_user_data(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            return redirect(url_for('index'))
        flash("Invalid username or password.")
    return render_template('auth.html', action="Login")

@app.route('/logout')
@limiter.limit("5 per 15 seconds")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    username = session['username']
    user_data = get_user_data(username)
    
    if user_data is None:
        session.pop('username', None)
        return redirect(url_for('register'))
        
    # Safe upgrades
    if 'subscriptions' not in user_data: user_data['subscriptions'] = []
    if 'savings_goals' not in user_data: user_data['savings_goals'] = {}
    if 'debts' not in user_data: user_data['debts'] = {}
    if 'last_billed_month' not in user_data: user_data['last_billed_month'] = ""

    current_month = datetime.now().strftime("%Y-%m")

    if user_data['last_billed_month'] != current_month and len(user_data['subscriptions']) > 0:
        for sub in user_data['subscriptions']:
            user_data['transactions'].append({
                "type": "expense",
                "amount": float(sub['amount']),
                "category": "Fixed Bills",
                "description": f"{sub['name']} (Auto-logged)",
                "date": datetime.now().strftime("%Y-%m-%d")
            })
        user_data['last_billed_month'] = current_month
        save_user_data(username, user_data) # Save immediately so they show up
        
    currency_symbol = CURRENCIES.get(user_data.get('currency', 'USD'), '$')
    
    if request.method == 'POST':
        try:
            if 'amount' in request.form and 'type' in request.form:
                user_data['transactions'].append({
                    "id": str(uuid.uuid4()),
                    "type": request.form.get('type', 'expense'),
                    "amount": float(request.form['amount']),
                    "category": request.form['category'],
                    "description": request.form['description'],
                    "date": request.form.get('date', datetime.now().strftime("%Y-%m-%d"))
                })
                flash("Transaction logged successfully!")
                
            elif 'budget_amount' in request.form:
                safe_cat = sanitize_key(request.form['budget_category'])
                if safe_cat: user_data['budgets'][safe_cat] = float(request.form['budget_amount'])
                flash("Budget updated!")
                
            elif 'sub_amount' in request.form:
                user_data['subscriptions'].append({"name": request.form['sub_name'], "amount": float(request.form['sub_amount'])})
                
            elif 'goal_target' in request.form:
                safe_goal = sanitize_key(request.form['goal_name'])
                if safe_goal: user_data['savings_goals'][safe_goal] = {"target": float(request.form['goal_target']), "saved": 0.0}
                
            elif 'add_to_goal' in request.form:
                goal_name = request.form['goal_name'] 
                if goal_name in user_data['savings_goals']: 
                    user_data['savings_goals'][goal_name]['saved'] += float(request.form['add_to_goal'])
                    
            elif 'debt_principal' in request.form:
                safe_debt = sanitize_key(request.form['debt_name'])
                if safe_debt: user_data['debts'][safe_debt] = {"principal": float(request.form['debt_principal']), "rate": float(request.form.get('debt_rate', 0)), "paid": 0.0}
                
            elif 'pay_debt' in request.form:
                debt_name = request.form['debt_name']
                if debt_name in user_data['debts']: 
                    user_data['debts'][debt_name]['paid'] += float(request.form['pay_debt'])
            
            save_user_data(username, user_data)
            
        except ValueError:
            flash("Error: Please enter a valid numerical amount.")
            
        return redirect(url_for('index'))

    transactions = user_data['transactions']
    for i, t in enumerate(transactions): t['id'] = i
    subs = user_data['subscriptions']
    for i, s in enumerate(subs): s['id'] = i
    
    selected_month = request.args.get('month', current_month)
    all_months = sorted(list(set(t['date'][:7] for t in transactions)), reverse=True)
    
    display_transactions = [t for t in transactions if t['date'].startswith(selected_month)] if selected_month else transactions
    total_income = sum(t['amount'] for t in display_transactions if t['type'] == 'income')
    total_expense = sum(t['amount'] for t in display_transactions if t['type'] == 'expense')
    net_balance = total_income - total_expense
    
    category_totals = {}
    for t in display_transactions:
        if t['type'] == 'expense': category_totals[t['category']] = category_totals.get(t['category'], 0) + t['amount']

    insights = []
    for cat, limit in user_data.get('budgets', {}).items():
        spent = category_totals.get(cat, 0)
        if limit > 0 and (spent / limit) >= 0.85:
            insights.append({"icon": "alert-triangle", "color": "var(--warning)", "msg": f"Careful! You've used {int((spent/limit)*100)}% of your {cat} budget."})

    if net_balance < 0:
        insights.append({"icon": "trending-down", "color": "var(--danger)", "msg": f"You are currently running a deficit of {currency_symbol}{abs(net_balance):.2f} this month."})
    elif net_balance > 0 and total_income > 0:
        savings_rate = (net_balance / total_income) * 100
        insights.append({"icon": "trending-up", "color": "var(--success)", "msg": f"Great job! You are saving {savings_rate:.1f}% of your income this month."})
    
    if not insights:
        insights.append({"icon": "check-circle", "color": "var(--primary)", "msg": "Your finances are looking stable. Keep logging your transactions!"})

    recent_txs = sorted(transactions, key=lambda x: x['date'], reverse=True)[:5]

    return render_template('dashboard.html', 
                           recent_transactions=recent_txs,
                           total_income=total_income, total_expense=total_expense, net_balance=net_balance,
                           category_totals=category_totals, all_months=all_months, selected_month=selected_month,
                           currencies=CURRENCIES, user_currency=user_data.get('currency', 'USD'), currency_symbol=currency_symbol,
                           budgets=user_data.get('budgets', {}), subscriptions=subs, total_subs=sum(s['amount'] for s in subs),
                           savings_goals=user_data.get('savings_goals', {}), debts=user_data.get('debts', {}),
                           insights=insights, username=username)

@app.route('/transactions')
@limiter.limit("5 per 15 seconds")
@login_required
def transactions():
    user_data = get_user_data(session['username'])
    if user_data is None: return redirect(url_for('logout'))
    currency_symbol = CURRENCIES.get(user_data.get('currency', 'USD'), '$')
    
    transactions = user_data['transactions']
    for i, t in enumerate(transactions): t['id'] = i

    selected_month = request.args.get('month', '')
    search_query = request.args.get('q', '').lower()
    all_months = sorted(list(set(t['date'][:7] for t in transactions)), reverse=True)
    
    display_transactions = transactions
    if selected_month: display_transactions = [t for t in display_transactions if t['date'].startswith(selected_month)]
    if search_query: display_transactions = [t for t in display_transactions if search_query in t['category'].lower() or search_query in t['description'].lower()]

    PER_PAGE = 15
    page = request.args.get('page', 1, type=int)
    display_transactions.sort(key=lambda x: x['date'], reverse=True)
    total_pages = max(1, (len(display_transactions) + PER_PAGE - 1) // PER_PAGE)
    paginated_transactions = display_transactions[(page - 1) * PER_PAGE : page * PER_PAGE]

    return render_template('transactions.html', transactions=paginated_transactions, all_months=all_months, selected_month=selected_month, search_query=search_query, page=page, total_pages=total_pages, currencies=CURRENCIES, user_currency=user_data.get('currency', 'USD'), currency_symbol=currency_symbol, username=session['username'])

@app.route('/analytics')
@limiter.limit("5 per 15 seconds")
@login_required
def analytics():
    user_data = get_user_data(session['username'])
    if user_data is None: return redirect(url_for('logout'))
    currency_symbol = CURRENCIES.get(user_data.get('currency', 'USD'), '$')
    
    transactions = user_data['transactions']
    selected_month = request.args.get('month', datetime.now().strftime("%Y-%m"))
    all_months = sorted(list(set(t['date'][:7] for t in transactions)), reverse=True)
    
    trend_data = {}
    monthly_breakdown = {'labels': [], 'income': [], 'expense': []}
    
    for m in list(reversed(all_months[:6])):
        m_tx = [t for t in transactions if t['date'].startswith(m)]
        inc = sum(t['amount'] for t in m_tx if t['type'] == 'income')
        exp = sum(t['amount'] for t in m_tx if t['type'] == 'expense')
        trend_data[m] = inc - exp
        monthly_breakdown['labels'].append(m)
        monthly_breakdown['income'].append(inc)
        monthly_breakdown['expense'].append(exp)
    
    display_transactions = [t for t in transactions if t['date'].startswith(selected_month)] if selected_month else transactions
    category_totals = {}
    for t in display_transactions:
        if t['type'] == 'expense': category_totals[t['category']] = category_totals.get(t['category'], 0) + t['amount']
    top_expenses = sorted([t for t in display_transactions if t['type'] == 'expense'], key=lambda x: x['amount'], reverse=True)[:5]

    return render_template('analytics.html', trend_data=trend_data, category_totals=category_totals, monthly_breakdown=monthly_breakdown, top_expenses=top_expenses, all_months=all_months, selected_month=selected_month, currencies=CURRENCIES, user_currency=user_data.get('currency', 'USD'), currency_symbol=currency_symbol, username=session['username'])

@app.route('/settings')
@limiter.limit("5 per 15 seconds")
@login_required
def settings():
    user_data = get_user_data(session['username'])
    if user_data is None: return redirect(url_for('logout'))
    
    transactions = user_data.get('transactions', [])
    all_months = sorted(list(set(t['date'][:7] for t in transactions)), reverse=True)
    
    return render_template('settings.html', 
                           currencies=CURRENCIES, 
                           user_currency=user_data.get('currency', 'USD'),
                           tx_count=len(transactions),
                           all_months=all_months,
                           username=session['username'])

@app.route('/update_password', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def update_password():
    user_data = get_user_data(session['username'])
    new_password = request.form.get('new_password')
    if new_password:
        user_data['password_hash'] = generate_password_hash(new_password)
        save_user_data(session['username'], user_data)
        flash("Password updated successfully!")
    return redirect(url_for('settings'))

@app.route('/wipe_data', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def wipe_data():
    user_data = get_user_data(session['username'])
    # Danger Zone: Clears all transactions but keeps budgets/goals
    user_data['transactions'] = []
    save_user_data(session['username'], user_data)
    flash("All transactions have been permanently deleted.")
    return redirect(url_for('settings'))

@app.route('/set_currency', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def set_currency():
    user_data = get_user_data(session['username'])
    user_data['currency'] = request.form.get('currency', 'USD')
    save_user_data(session['username'], user_data)
    return redirect(request.referrer or url_for('index'))

@app.route('/delete/<tx_id>', methods=['POST'])  
@limiter.limit("5 per 15 seconds")
@login_required
def delete_transaction(tx_id):
    user_data = get_user_data(session['username'])
    
    original_length = len(user_data['transactions'])
    user_data['transactions'] = [t for t in user_data['transactions'] if t.get('id') != tx_id]
    
    if len(user_data['transactions']) < original_length:
        save_user_data(session['username'], user_data)
        flash("Transaction deleted.")
        
    return redirect(request.referrer or url_for('index'))

@app.route('/delete_budget/<category>', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def delete_budget(category):
    user_data = get_user_data(session['username'])
    if category in user_data['budgets']:
        del user_data['budgets'][category]
        save_user_data(session['username'], user_data)
    return redirect(url_for('index'))

@app.route('/delete_sub/<int:index>', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def delete_sub(index):
    user_data = get_user_data(session['username'])
    if 0 <= index < len(user_data['subscriptions']):
        user_data['subscriptions'].pop(index)
        save_user_data(session['username'], user_data)
    return redirect(url_for('index'))

@app.route('/delete_goal/<goal_name>', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def delete_goal(goal_name):
    user_data = get_user_data(session['username'])
    if goal_name in user_data['savings_goals']:
        del user_data['savings_goals'][goal_name]
        save_user_data(session['username'], user_data)
    return redirect(url_for('index'))

@app.route('/delete_debt/<debt_name>', methods=['POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def delete_debt(debt_name):
    user_data = get_user_data(session['username'])
    if debt_name in user_data['debts']:
        del user_data['debts'][debt_name]
        save_user_data(session['username'], user_data)
    return redirect(url_for('index'))

@app.route('/edit/<tx_id>', methods=['GET', 'POST'])
@limiter.limit("5 per 15 seconds")
@login_required
def edit_transaction(tx_id):
    user_data = get_user_data(session['username'])
    
    # Find the specific transaction dictionary
    transaction = next((t for t in user_data['transactions'] if t.get('id') == tx_id), None)
    
    if not transaction: 
        flash("Transaction not found.")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            transaction['type'] = request.form.get('type', transaction['type'])
            transaction['amount'] = float(request.form['amount'])
            transaction['category'] = request.form['category']
            transaction['description'] = request.form['description']
            transaction['date'] = request.form['date']
            
            save_user_data(session['username'], user_data)
            flash("Transaction updated!")
            return redirect(url_for('transactions'))
        except ValueError: 
            flash("Error: Invalid number format.")
            
    return render_template('edit.html', transaction=transaction, currency_symbol=CURRENCIES.get(user_data.get('currency', 'USD'), '$'), username=session['username'])

@app.route('/export')
@limiter.limit("5 per 15 seconds")
@login_required
def export_transactions():
    user_data = get_user_data(session['username'])
    transactions = user_data['transactions']
    selected_month = request.args.get('month', '')
    search_query = request.args.get('q', '').lower()
    user_currency = user_data.get('currency', 'USD')
    
    if selected_month: transactions = [t for t in transactions if t['date'].startswith(selected_month)]
    if search_query: transactions = [t for t in transactions if search_query in t['category'].lower() or search_query in t['description'].lower()]
        
    total_income = sum(t['amount'] for t in transactions if t['type'] == 'income')
    total_expense = sum(t['amount'] for t in transactions if t['type'] == 'expense')
    net_balance = total_income - total_expense
        
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    elements = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name='CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#0F172A'), spaceAfter=5)
    subtitle_style = ParagraphStyle(name='CustomSubtitle', parent=styles['Normal'], fontSize=11, textColor=colors.HexColor('#64748B'), spaceAfter=20)
    
    elements.append(Paragraph("FinancePro Statement", title_style))
    report_period = selected_month if selected_month else 'All Time'
    gen_date = datetime.now().strftime('%Y-%m-%d %H:%M')
    elements.append(Paragraph(f"<b>Period:</b> {report_period} &nbsp;&nbsp;&nbsp; | &nbsp;&nbsp;&nbsp; <b>Generated:</b> {gen_date}", subtitle_style))
    elements.append(Spacer(1, 10))
    
    kpi_data = [["Total Income", "Total Expenses", "Net Balance"], [f"+ {total_income:.2f} {user_currency}", f"- {total_expense:.2f} {user_currency}", f"{net_balance:.2f} {user_currency}"]]
    kpi_table = Table(kpi_data, colWidths=[171, 171, 171])
    kpi_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'), ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'), ('FONTSIZE', (0,0), (-1,0), 10), ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#64748B')), ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'), ('FONTSIZE', (0,1), (-1,1), 16), ('TEXTCOLOR', (0,1), (0,1), colors.HexColor('#10B981')), ('TEXTCOLOR', (1,1), (1,1), colors.HexColor('#E11D48')), ('TEXTCOLOR', (2,1), (2,1), colors.HexColor('#4F46E5')),
        ('TOPPADDING', (0,1), (-1,1), 5), ('BOTTOMPADDING', (0,1), (-1,1), 20), ('LINEBELOW', (0,1), (-1,1), 1, colors.HexColor('#E2E8F0'))
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 20))
    
    table_data = [['Date', 'Type', 'Category', 'Description', f'Amount ({user_currency})']]
    for t in transactions:
        amount_str = f"+{t['amount']:.2f}" if t['type'] == 'income' else f"-{t['amount']:.2f}"
        table_data.append([t['date'], t['type'].capitalize(), t['category'], t['description'], amount_str])
        
    t = Table(table_data, colWidths=[70, 60, 100, 195, 90])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke), ('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('ALIGN', (4, 0), (4, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, 0), 11), ('TOPPADDING', (0, 0), (-1, 0), 12), ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'), ('FONTSIZE', (0, 1), (-1, -1), 10), ('TOPPADDING', (0, 1), (-1, -1), 10), ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))
    
    elements.append(t)
    doc.build(elements)
    pdf_out = buffer.getvalue()
    buffer.close()
    
    response = Response(pdf_out, mimetype='application/pdf')
    filename = f"FinancePro_Statement_{selected_month if selected_month else 'All_Time'}.pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response

if __name__ == '__main__':
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(host='0.0.0.0', port=5000, debug=is_debug)