# ---- Base ----
FROM python:alpine AS base

#
# ---- Dependencies ----
FROM base AS dependencies
# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt
 
#
# ---- Release ----
FROM dependencies AS release
# copy project source file(s)
WORKDIR /
COPY cloudflare-firewall-dynip.py .
CMD ["python", "-u", "/cloudflare-firewall-dynip.py", "--repeat"]