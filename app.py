from flask import Flask, make_response, request, jsonify
import psycopg2
import jwt
from functools import wraps

from flask_cors import CORS

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})

# Database connection parameters
db_params = {
    'dbname': 'wsclpgli',
    'user': 'wsclpgli',
    'password': 'pWTfSzrPZjTY6-v8x3T8XN-1XMED8JJr',
    'host': 'satao.db.elephantsql.com',
    'port': '5432',
}


# Function to establish a database connection
def get_db_connection():
    conn = psycopg2.connect(**db_params)
    return conn


def generate_jwt_cookie(user_id):
    # Define a secret key for signing the token (change this to a secure secret)
    secret_key = 'your_secret_key_here'

    # Create a payload containing the user_id
    payload = {'user_id': user_id}

    # Generate the JWT token
    token = jwt.encode(payload, secret_key, algorithm='HS256')

    return token

# Secret key for verifying JWT tokens


SECRET_KEY = 'your_secret_key_here'
# Replace with your actual secret key


# Define the decorator function
def check_valid_jwt_cookie(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Get the JWT token from the cookie
        jwt_cookie = request.cookies.get('jwt_cookie')

        if jwt_cookie:
            try:
                # Verify the JWT token with the secret key
                payload = jwt.decode(jwt_cookie, SECRET_KEY, algorithms=['HS256'])
                # You can add more validation checks if needed
                print(payload)
                # Call the original function with the payload as an argument
                return func(payload, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'JWT token has expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid JWT token'}), 401

        # If no JWT cookie is found or validation fails, return an error response
        return jsonify({'error': 'JWT token is missing or invalid'}), 401

    return wrapper

# ______________________Create tables____________________________________

# Function to create the User table


def create_user_table():
    try:
        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL statement to create the User table with the 'admin' field as boolean
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS "User" (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password VARCHAR(120) NOT NULL,
                admin BOOLEAN
            )
        '''

        # Execute the SQL statement to create the User table
        cursor.execute(create_table_sql)

        # Commit the transaction
        conn.commit()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error creating User table: {str(e)}")


# Create the User table (call this function once to create the table)
create_user_table()


# register a user


@app.route('/register', methods=['POST'])
def index():
    try:
        username = request.json.get("username")
        email = request.json.get("email")
        password = request.json.get("password")
        admin = request.json.get("admin", False)

        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        values = (username, email, password, admin)
        # Insert a new user record with 'admin' set to True
        cursor.execute(
            f"INSERT INTO \"User\" (username, email, password, admin) VALUES (%s, %s, %s, %s)", values)

        # Commit the transaction
        conn.commit()

        cursor.close()
        conn.close()
        resp = make_response(jsonify(f"Inserted User: {username}"))
        token = generate_jwt_cookie(username)
        resp.set_cookie('jwt_session', token, httponly=True, path='/', domain='http://127.0.0.1')
        return resp, 200
    except Exception as e:
        return jsonify(f"Error: {str(e)}"), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Extract username and password from the JSON data
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL query to select a user by username and password
        select_query = 'SELECT * FROM "User" WHERE username = %s AND password = %s'

        # Define the values to be used in the query
        values = (username, password)

        # Execute the SQL query
        cursor.execute(select_query, values)

        # Fetch the user record
        user = cursor.fetchone()

        if user:
            # User credentials are correct, generate a JWT token
            user_id = user[0]
            token = generate_jwt_cookie(user_id)

            # Close the cursor and the connection
            cursor.close()
            conn.close()

            # Create a Flask response object
            resp = make_response(jsonify({'message': 'Login successful'}))

            # Set the JWT token as a cookie in the response
            resp.set_cookie('jwt_session', token, httponly=True, path='/', domain='127.0.0.1', max_age=3600000)

            return resp, 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@check_valid_jwt_cookie
@app.route('/all_user', methods=['GET'])
def get_all_users():
    try:
        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL query to select all users
        select_query = 'SELECT * FROM "User"'

        # Execute the SQL query
        cursor.execute(select_query)

        # Fetch all user records
        users = cursor.fetchall()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

        # Prepare the response in JSON format
        user_list = [{'id': user[0], 'username': user[1], 'email': user[2], 'password': user[3], 'admin': user[4]}
                     for user in users]

        return jsonify({'users': user_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# _________________________Context of products start here________________________________________________


def create_product_table():
    try:
        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL statement to create the Product table
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS "Product" (
                product_id SERIAL PRIMARY KEY,
                product_name VARCHAR(100) NOT NULL,
                price FLOAT NOT NULL,
                details TEXT
            )
        '''

        # Execute the SQL statement to create the Product table
        cursor.execute(create_table_sql)

        # Commit the transaction
        conn.commit()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error creating Product table: {str(e)}")


# Create the Product table (call this function once to create the table)
create_product_table()


@check_valid_jwt_cookie
@app.route('/add_product', methods=['POST'])
def insert_product():
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Extract product data from the JSON data
        product_name = data.get('product_name')
        price = data.get('price')
        details = data.get('details')

        if not product_name or not price or not details:
            return jsonify({'error': 'Product name, price, and details are required'}), 400

        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the INSERT SQL statement
        insert_sql = '''
            INSERT INTO "Product" (product_name, price, details)
            VALUES (%s, %s, %s)
        '''

        # Define the values
        values = (product_name, price, details)

        # Execute the INSERT statement
        cursor.execute(insert_sql, values)

        # Commit the transaction
        conn.commit()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

        return jsonify({'message': 'Product inserted successfully'}), 201  # 201 indicates resource creation

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@check_valid_jwt_cookie
@app.route('/all_products', methods=['GET'])
def get_all_products():
    try:
        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL query to select all products
        select_query = 'SELECT * FROM "Product"'

        # Execute the SQL query
        cursor.execute(select_query)

        # Fetch all product records
        products = cursor.fetchall()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

        # Prepare the response as a list of dictionaries
        product_list = [{'product_id': product[0], 'product_name': product[1], 'price': product[2],
                         'details': product[3]} for product in products]

        return jsonify({'products': product_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#  __cart________________________________________________


def create_cart_table():
    try:
        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL statement to create the "cart" table
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS "cart_1" (
                id SERIAL PRIMARY KEY,
                product_name VARCHAR(100) NOT NULL,
                count INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES "User" (id)
            )
        '''

        # Execute the SQL statement to create the "cart" table
        cursor.execute(create_table_sql)

        # Commit the transaction
        conn.commit()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error creating Cart table: {str(e)}")


create_cart_table()


@check_valid_jwt_cookie
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    try:
        # Get the JWT token from the request cookie
        jwt_cookie = request.cookies.get('jwt_cookie')

        if not jwt_cookie:
            return jsonify({'error': 'JWT token is missing'}), 401

        # Verify and decode the JWT token to extract the user ID
        try:
            user_id = jwt.decode(jwt_cookie, 'your_secret_key_here', algorithms=['HS256'])['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'JWT token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid JWT token'}), 401

        # Get the JSON data from the request
        data = request.get_json()

        # Extract product data from the JSON data
        product_name = data.get('product_name')
        count = data.get('count')

        if not product_name or not count:
            return jsonify({'error': 'Product name and count are required'}), 400

        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL statement to insert the cart item
        insert_sql = '''
            INSERT INTO "cart_1" (product_name, count, user_id)
            VALUES (%s, %s, %s)
        '''

        # Define the values
        values = (product_name, count, user_id)

        # Execute the INSERT statement
        cursor.execute(insert_sql, values)

        # Commit the transaction
        conn.commit()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

        return jsonify({'message': 'Product added to cart successfully'}), 201  # 201 indicates resource creation

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@check_valid_jwt_cookie
@app.route('/cart', methods=['GET'])
def get_cart():
    try:
        # Get the JWT token from the request cookie
        jwt_cookie = request.cookies.get('jwt_cookie')

        if not jwt_cookie:
            return jsonify({'error': 'JWT token is missing'}), 401

        # Verify and decode the JWT token to extract the user ID
        try:
            user_id = jwt.decode(jwt_cookie, 'your_secret_key_here', algorithms=['HS256'])['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'JWT token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid JWT token'}), 401

        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL statement to fetch all products in the cart for the user
        select_sql = '''
            SELECT product_name, count
            FROM "cart_1"
            WHERE user_id = %s
        '''

        # Define the value for the user_id
        values = (user_id,)

        # Execute the SELECT statement
        cursor.execute(select_sql, values)

        # Fetch all rows as a list of dictionaries
        cart_items = []
        for row in cursor.fetchall():
            cart_item = {
                'product_name': row[0],
                'count': row[1]
            }
            cart_items.append(cart_item)

        # Close the cursor and the connection
        cursor.close()
        conn.close()

        return jsonify({'cart': cart_items}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@check_valid_jwt_cookie
@app.route('/remove_all_cart', methods=['POST'])
def remove_all_from_cart():
    try:
        # Get the JWT token from the request cookie
        jwt_cookie = request.cookies.get('jwt_cookie')

        if not jwt_cookie:
            return jsonify({'error': 'JWT token is missing'}), 401

        # Verify and decode the JWT token to extract the user ID
        try:
            user_id = jwt.decode(jwt_cookie, 'your_secret_key_here', algorithms=['HS256'])['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'JWT token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid JWT token'}), 401

        # Establish a database connection
        conn = get_db_connection()

        # Create a cursor
        cursor = conn.cursor()

        # Define the SQL statement to remove all products from the cart for the user
        delete_sql = '''
            DELETE FROM "cart_1"
            WHERE user_id = %s
        '''

        # Define the value for the user_id
        values = (user_id,)

        # Execute the DELETE statement
        cursor.execute(delete_sql, values)

        # Commit the transaction
        conn.commit()

        # Close the cursor and the connection
        cursor.close()
        conn.close()

        return jsonify({'message': 'All products removed from the cart successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.logger.warning("Starting the Server")
    app.run(debug=True)
