# Notes


??? nSloc/Complexity

# Terms 

1. Mid-flight account -> user in the contract who is doing a transaction in the moment

#  About



- Each vault works with 1 tokens

### Messages
How it works:
1. Take private key + message (could be data, function selector, parameters)
2. Smash it into Ellipticc Curve Digital Signature Algoritm (ECDSA)
    1. This outputs v,r,s
    2. W can use these values to verify someone signature using `ecrecover`

How verification works:

1. Get the signed message
    1. Break into v,r,s
2. Get the data itself
3. Use it as input parameters for `ecrecover`

# Potential attacks vectors


# Questions
1. What is an Operator
2. What is L1 and L2
3. What is a signature (v,r,s)



# Ideas 

1. 


# Tools
- **Slither**: Se utiliza para el análisis estático de contratos inteligentes en Solidity, detectando vulnerabilidades y optimizaciones potenciales.
  
- **Aderyn**: Es una herramienta de auditoría automática que revisa contratos inteligentes para encontrar posibles fallos de seguridad.