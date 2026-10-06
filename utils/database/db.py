import mysql.connector


def get_connection():

    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="rishi@123",
        database="scamshield"
    )


def save_scan(
    scan_type,
    input_data,
    risk,
    score
):

    connection = get_connection()

    cursor = connection.cursor()

    query = """
    INSERT INTO scan_history
    (scan_type, input_data, risk_level, risk_score)
    VALUES (%s, %s, %s, %s)
    """

    cursor.execute(
        query,
        (
            scan_type,
            input_data,
            risk,
            score
        )
    )

    connection.commit()

    cursor.close()
    connection.close()


def get_scan_history():

    connection = get_connection()

    cursor = connection.cursor(
        dictionary=True
    )

    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    cursor.close()
    connection.close()

    return records