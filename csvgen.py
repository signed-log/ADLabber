import argparse
import secrets
import unicodedata
from textwrap import shorten

import pandas as pd
from faker import Faker
import validators

fake = Faker("fr_FR")
Faker.seed(secrets.randbelow(5000000000000))


def validate_domain(astring):
    if not validators.domain(astring):
        raise argparse.ArgumentTypeError("Domain name is invalid")
    else:
        return astring


parser = argparse.ArgumentParser(
    description="Generate mock user data for a lab AD session")

parser.add_argument("domain_name", type=validate_domain, nargs=1)
parser.add_argument("root_ou", type=str, nargs=1)

args = parser.parse_args()

DomainName = args.domain_name[0].lower()
RootOU = args.root_ou[0].lower()


def strip_accents(s):
    # Code licensed under CC-BY-SA 3.0 : https://stackoverflow.com/a/518232
    return ''.join(c for c in unicodedata.normalize('NFD', s)
                   if unicodedata.category(c) != 'Mn')


def gen_data():
    FirstName = []
    LastName = []
    EmployeeID = []
    UserPrincipalName = []
    SamAccountName = []
    AccountPassword = []
    PostalCode = []
    Country = []
    for id in range(150):
        FirstName.append(strip_accents(fake.first_name()))
        LastName.append(strip_accents(fake.last_name()))
        EmployeeID.append(id)
        UserPrincipalName.append(
            f"{FirstName[-1][0].lower()}.{shorten(''.join(filter(str.isalpha, LastName[-1])), width=13, placeholder='').lower()}@{DomainName}"
        )
        SamAccountName.append(UserPrincipalName[-1].split('@')[0])
        AccountPassword.append(secrets.token_urlsafe(32))
        PostalCode.append(fake.postcode())
        Country.append("FR")
    return {
        "EmployeeID": EmployeeID,
        "FirstName": FirstName,
        "LastName": LastName,
        "UserPrincipalName": UserPrincipalName,
        "SamAccountName": SamAccountName,
        "AccountPassword": AccountPassword,
        "PostalCode": PostalCode,
        "Country": Country
    }


if __name__ == '__main__':
    data = gen_data()
    df = pd.DataFrame(data)
    with open("./UserMockList.csv", "w", newline="") as f:
        df.to_csv(f, index=False)
