import csv

def read_csv_to_array(csv_file_path):
    data_set = set()

    with open('./uscities.csv', 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            city_state = f"{row['city']}, {row['state']}"
            data_set.add(city_state)

    # Convert set back to list
    data_array = list(data_set)
    return data_array

# Example usage:
csv_file_path = 'uscities.csv'  # Replace with the path to your CSV file
cities_data = read_csv_to_array(csv_file_path)


