# oidcprimer
This one-day course is an introduction to the next generation identity management and authorisation protocols and
their constituent components (OAuth2/JW*/OIDC/UMA).

The second part of the programme includes a more practical look at relevant tools and libraries (in Python, Java and/or PHP).

Who is it for?: Developers of resources for web and mobile will especially benefit from this course.

**Learning objectives:**

- Understand the principles of OIDC and OAuth2
- How to choose the OIDC most appropriate authentication flow for each use case
- Know how to move in the official documentation
- Implement an OIDC Resource Provider both with software libraries and with HTTP server modules

**Trainers:** Andrea Biancini, Davide Vaghetti

# Assignment instructions
Download this repository.
Choose one of the following assignments and follow the linked instructions:

1. Implement a OAuth2 client: [instructions](oauth2-client/README.md)
1. Implement a Relying Party in Python: [instructions](oidc-python-rp/README.md)
1. Implement a Relying Party in Java: [instructions](oidc-java-rp/README.md)
1. Use the Apache module ``mod_auth_openidc`` as a black-box Relying Party: [instructions](apache_skeleton/README.md)
 
After completing the assignments, experiment with your setup by applying the
suggested tweaks in [OpenID Connect Parameter options](parameter_exercises.md). 

All OpenID Connect specifications can be found at http://openid.net/developers/specs/.
