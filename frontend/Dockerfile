# --- Stage 1: Build the React App ---
# UPDATED: Changed from node:18-alpine to node:22-alpine for Vite 7 support
FROM node:22-alpine as builder

# Set working directory
WORKDIR /app

# Copy package files first (for better caching)
COPY package.json package-lock.json ./

# Install dependencies
# We use 'ci' (clean install) if lockfile exists, otherwise 'install'
RUN npm ci || npm install

# Copy the rest of the source code
COPY . .

# Build the static files (Output goes to /app/dist)
RUN npm run build

# --- Stage 2: Serve with Nginx ---
FROM nginx:alpine

# Copy the build output from Stage 1 to Nginx's html folder
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy our custom Nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]