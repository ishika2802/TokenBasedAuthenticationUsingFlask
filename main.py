from app import create_app

if __name__ == '__main__':
    app = create_app()
    # print(f"Template folder path: {os.path.join(os.getcwd(), 'templates')}")

    app.run(debug=True)  # Ensure debug mode is on