# Set the path of your file
file_path = "/root/users.db"

# Use a try-except block to catch any errors
try:
    # Open the file in read mode
    with open(file_path, 'r') as file:
        # Read the contents of the file
        contents = file.readlines()

    # Print the contents
    for line in contents:
        print(line.strip())
except FileNotFoundError:
    print(f"The file at {file_path} was not found.")
except:
    print("An error occurred while trying to read the file.")
