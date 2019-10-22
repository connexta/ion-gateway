#!/usr/bin/env bash

printf "Retrieving access token from Keycloak for admin:admin... (waiting up to 30 seconds)"
token_response=$(curl -X POST "http://keycloak:8080/auth/realms/master/protocol/openid-connect/token" \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=admin" \
-d "password=admin" \
-d "grant_type=password" \
-d "client_id=login-client")

access_token=""
count=0

# parse out access token from JSON reponse
# sed command removes {}" characters from the response, replaces : with space, and puts each key-pair on a new line
access_token=$(echo "$token_response" | sed -z "s/[{}\"]//g; s/:/ /g ;s/,/\n/g" | grep -i "access_token" | awk '{print $2}')
while [ -z "$access_token" ] && [ $count -lt 6 ]; do
  sleep 5
  ((count++))
  access_token=$(echo "$token_response" | sed -z "s/[{}\"]//g; s/:/ /g ;s/,/\n/g" | grep -i "access_token" | awk '{print $2}')
done

if [ -z "$access_token" ]; then
  printf "\nCould not fetch token for admin from keycloak. Keycloak may not be up, try waiting a moment and running \
./accesstoken.sh again. Also ensure that 'keycloak' is in your hosts file.\n"
else
  printf "\n$access_token\n"
fi
