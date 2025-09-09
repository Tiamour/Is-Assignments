#task 1 and 2
one_list=input().split()
second_list=input().split()
new_list=one_list+second_list
new_list.sort()
print(new_list)
print(max(new_list))
print(min(new_list))
#task 3
birthdays = {
    "Ali": "03/14/1879",
    "Hamza": "01/17/1706",
    "Ahmad": "12/10/1815"}
print("Welcome to the birthday dictionary. We know the birthdays of:")
for name in birthdays:
    print(name)
person = input("Who's birthday do you want to look up? ")
if person in birthdays:
    print(person, "->", birthdays[person])
else:
    print(f"Sorry, we don’t have {person}'s birthday in our dictionary.")
#task 3
sample_dict = {
    "name": "Kelly",
    "age": 25,
    "salary": 8000,
    "city": "New york"}
keys = ["name", "salary"]
new_dict = {}
for k in keys:
    new_dict[k] = sample_dict[k]

print(new_dict)

