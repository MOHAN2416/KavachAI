FROM mcr.microsoft.com/playwright:v1.42.1-jammy

# Set working directory
WORKDIR /usr/src/app

# Build toolchain for native modules (e.g. better-sqlite3). If no prebuilt
# binary is available for this platform/Node ABI, npm falls back to compiling
# from source with node-gyp, which needs python3, make and a C/C++ compiler.
# The Playwright base image does not ship these, so install them here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy root and frontend package definitions
COPY package*.json ./
COPY frontend/package*.json ./frontend/

# Install dependencies (Playwright is installed during npm install automatically)
RUN npm install
RUN npm --prefix frontend install

# Copy application source code
COPY . .

# Build both TypeScript backend and Vite React frontend
RUN npm run build

# Expose default Express port
EXPOSE 3000

# Set production variables
ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/data

# Start application
CMD [ "npm", "start" ]
