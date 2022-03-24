FROM python:2

WORKDIR /usr/src/app

# COPY . .
COPY . .

# RUN pip3 install -r requirement.txt
RUN pip install -U Flask
RUN pip install flask-restful
RUN pip install werkzeug
RUN pip install flask_cors
RUN pip install requests
CMD [ "python", "./server.py"]