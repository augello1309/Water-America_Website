How To run the website
1. Open project with vscode
2. Type in the command line "flask run"
3. Go to localhost:5000

How to close the website
1. Press Ctrl C in command line
2. (If you pressed Ctrl Z, you must kill the port on your local machine. The command for that is sudo kill -9 $(sudo lsof -t -i:5000))

Dependencies Needed
1. flask
2. flask_pymongo
3. usps (pip install usps-api)
4. datetime
5. flask_bcrypt
6. flask_login
7. apscheduler
8. random
9. string
10. flask_mail
11. flask_session
12. bson
13. flask_simple_crypt
14. dotenv
15. os


- If you need to update pip:
`python -m pip install --user --upgrade pip` on windows with admin settings

- If you want to run it on a different port than the standard:
`flask run -h localhost -p 3000` where 3000 is the port
