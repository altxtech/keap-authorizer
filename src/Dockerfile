FROM python:3.12-alpine

# Create and set the working directory
WORKDIR /usr/src/app

# Copy only the requirements file first to leverage Docker caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire application code
COPY . .

# Expose the port your application will run on
EXPOSE 8080

# Use a non-root user
RUN adduser --system --no-create-home nonroot
USER nonroot

# Specify the command to run on container start
CMD ["waitress-serve", "--call", "keap_authorizer:create_app"]
