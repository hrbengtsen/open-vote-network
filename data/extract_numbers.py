import csv

file = open('vote_output.txt', 'r')
cost = []
energy = []
# Using for loop
for line in file:
    if "Transaction is finalized" in line:
        line_edit = line[132:]
        line_edit = line_edit.replace(' CCD (',',')
        line_edit = line_edit.replace(' NRG).\n', '')
        i = line_edit.index(",")
        cost.append(line_edit[0:i])
        energy.append(line_edit[i+1:])

with open('cost_csv_file.csv', 'w') as f:
    # create the csv writer
    writer = csv.writer(f)

    # write a row to the csv file
    writer.writerow(cost)

with open('energy_csv_file.csv', 'w') as f:
     # create the csv writer
    writer = csv.writer(f)

    # write a row to the csv file
    writer.writerow(energy)

