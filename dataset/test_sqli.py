from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///test.db')


def get_user(username):
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))
        return result.fetchall()
