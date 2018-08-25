FROM crossbario/crossbar

COPY .crossbar /node/.crossbar
COPY authenticator.py /node/

ENV PORT=8080
ENV TOKEN_VALIDATION_URL=http://localhost:8000/api/auth/validate-token/
