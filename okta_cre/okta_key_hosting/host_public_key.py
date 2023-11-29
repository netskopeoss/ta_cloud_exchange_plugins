import uvicorn
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
import json
import argparse

app = FastAPI()

parser = argparse.ArgumentParser(description ='Search some files')
parser.add_argument(
    '-k', '--keypath', metavar ='filepath',
    required = True, dest ='file_path',
    action ='append',
    help ='location to the public key'
)
parser.add_argument(
    '-p', '--port', metavar ='port',
    required = True, dest ='port',
    action ='append',
    help ='port to host the service'
)
args = parser.parse_args()
file_path = args.file_path[0]
port = int(args.port[0])

@app.get("/")
def fetch_details():
    return {"Details": "Server hosting the public-private key pair set."}

@app.get("/jwks", status_code=status.HTTP_200_OK)
def get_public_key():
    try:
        with open(f'{file_path}') as f:
            sample_response = json.load(f)
    except Exception as err:
        print(f"\nError occurred while fetching the contents of the Public Key file. Error {err}")
        raise err
    return JSONResponse(content=sample_response)

if __name__ == "__main__":
    uvicorn.run("host_public_key:app", host="0.0.0.0", port=port, reload=True)

