import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from detector import detect_attack
from logger import log_attack

app = FastAPI()

templates = Jinja2Templates(directory="templates")


@app.middleware("http")
async def threatshield_firewall(request: Request, call_next):

    path = request.url.path

    # allow homepage
    if path == "/":
        return await call_next(request)

    # get user input safely
    query = request.query_params.get("query")

    if query:

        result = detect_attack(query)
        if isinstance(result, tuple):
            attack = result[0]
            confidence = result[1] if len(result) > 1 else 1.0
        else:
            attack = result
            confidence = 1.0

        if attack.lower() != "normal":

            log_attack(query, attack, confidence=confidence, severity="HIGH")

            return templates.TemplateResponse(
                "blocked.html",
                {"request": request}
            )

    response = await call_next(request)

    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


@app.get("/search")
def search(query: str):

    return {
        "result": f"You searched for: {query}"
    }