#  образ Node.js на Alpine (лёгкий)
FROM node:20-alpine

# рабочая директория в контейнере
WORKDIR /app

# Копи package.json и package-lock.json (для оптимизации кэша)
COPY package*.json ./

# зависимости (включая dev-зависимости)
RUN npm install

# Копи проект в контейнер (кроме .dockerignore)
COPY . .

#порт, который использует приложение
EXPOSE 3000

# Запуск
CMD ["npm", "start"]
