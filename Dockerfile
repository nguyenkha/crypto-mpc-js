FROM node:10

COPY package.json yarn.lock /usr/src/app/

WORKDIR /usr/src/app

RUN yarn

COPY . /usr/src/app/

USER node

EXPOSE 3000

CMD ["yarn", "start"]
