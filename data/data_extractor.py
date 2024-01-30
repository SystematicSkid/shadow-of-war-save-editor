import sys
import os

def parse_roles(input_string):
    roles = []
    current_role = {}
    for line in input_string.splitlines():
        line = line.strip()
        if line.startswith('{'):
            current_role = {}
        elif line.startswith('}'):
            roles.append(current_role)
        elif '=' in line:
            key, value = line.split('=')
            current_role[key.strip()] = value.strip()
    return roles

def parse_roles_file(file_name):
    with open(file_name, 'r') as f:
        return parse_roles(f.read())

def role_get_percentage(role):
    weight_adjustment = max(float(role['WeightAdjustment']), 0.0001)
    return (1/(weight_adjustment * (1 + 0))) * 100    

def normalize_role_percentage(roles, percentage_sum):
    for role in roles:
        role['Percentage'] = role_get_percentage(role) / percentage_sum * 100

def get_role_percentage_sum(roles):
    percentage_sum = 0
    for role in roles:
        percentage_sum += role_get_percentage(role)
    return percentage_sum

def create_role_csv(roles):
    with open('roles.csv', 'w') as f:
        f.write('Role,Percentage\n')
        for role in roles:
            f.write('{0},{1}%\n'.format(role['Role'], role['Percentage']))

def main():
    # Input file = role_data.txt
    if len(sys.argv) < 2:
        print('usage: python data_extractor.py <file_name>')
        return
    file_name = sys.argv[1]
    if not os.path.exists(file_name):
        print('file does not exist')
        return
    roles = parse_roles_file(file_name)
    roles = [role for role in roles if float(role['WeightAdjustment']) != 0.000000]
    percentage_sum = get_role_percentage_sum(roles)
    normalize_role_percentage(roles, percentage_sum)
    for role in roles:
        print(role)

    create_role_csv(roles)

if __name__ == '__main__':
    main()