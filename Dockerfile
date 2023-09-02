FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y software-properties-common curl sudo

RUN curl -sL https://deb.nodesource.com/setup_18.x | sudo -E bash -
RUN apt-get install -y nodejs git git-core gcc make build-essential

RUN apt-get update
RUN apt-get install -y gconf-service libasound2 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 ca-certificates fonts-liberation libnss3 lsb-release xdg-utils wget ca-certificates libgbm-dev
RUN npm install -g yarn

COPY package.json .
RUN yarn

COPY . /application
WORKDIR /application

RUN yarn run build

CMD ["yarn", "run", "serve"]