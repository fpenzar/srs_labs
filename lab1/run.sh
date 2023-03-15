#!/bin/bash

MASTER_PWD=MasterPassword
WRONG_PWD=WrongPassword
RUN_PY="python3 symetric_crypto.py"

# TODO ovo se sigurno moze nekak ljepse napisati od ovoga

CMD="${RUN_PY} ${MASTER_PWD} init"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${MASTER_PWD} put www.fer.hr ferLozinka_1"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${MASTER_PWD} put www.fer.hr ferLozinka_2"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${MASTER_PWD} put www.index.hr citamVijesti"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${MASTER_PWD} get www.fer.hr"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${MASTER_PWD} get www.nisam_spremljen.com"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${WRONG_PWD} get www.fer.hr"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${WRONG_PWD} put www.fer.hr zabranjenaLozinka"
echo ${CMD}
${CMD}
echo ----------------------------------------
CMD="${RUN_PY} ${MASTER_PWD} get www.fer.hr"
echo ${CMD}
${CMD}
echo ----------------------------------------
