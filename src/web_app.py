from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def home():

    html = """
    <html>
    <head>
        <title>ThreatShield Protected Website</title>
        <style>
            body{
                background:#0b1220;
                color:white;
                font-family:Arial;
                text-align:center;
                padding-top:100px;
            }
            h1{color:#00e5ff;}
            input{
                padding:10px;
                width:300px;
                border-radius:5px;
            }
            button{
                padding:10px 20px;
                background:#00e5ff;
                border:none;
                border-radius:5px;
            }
        </style>
    </head>

    <body>

        <h1>🛡 ThreatShield Protected Website</h1>
        <p>This website is protected by AI Web Application Firewall</p>

        <form method="get" action="/search">

            <input name="query" placeholder="Search product">

            <button type="submit">Search</button>

        </form>

    </body>
    </html>
    """

    return html


@app.get("/search")
def search(query:str):

    return {"result": f"You searched for {query}"}