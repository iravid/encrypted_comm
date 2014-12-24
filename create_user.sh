#!/bin/bash

export PYTHONPATH="."

python server/UserManager.py $1

cp certificates/$1.{cert,priv} ./
