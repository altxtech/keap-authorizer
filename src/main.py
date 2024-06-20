from keap_authorizer import create_app
from dotenv import load_dotenv
load_dotenv()

def main():
    app = create_app()
    app.run()

if __name__ == "__main__":
    main()
