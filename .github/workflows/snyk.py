import json

def fromJSON(data:str):
    with open(data,'r') as file:
        res = file.read()
        json_data = json.loads(res)
        return json_data

class Vulnerabilite(object):
    def __init__(self,nom:str,sev:str,ind:int,info:str,ligne:str) -> None:
        self.nom = nom 
        self.sev = sev
        self.ind = ind
        self.info = info
        self.ligne = ligne
    def __repr__(self) -> str:
        return f"[{self.sev}] {self.nom}\n\tPath: {self.ligne}\n\tInfo: {self.info}"

    def __str__(self) -> str:
        return f"<p {self.color()}>[{self.sev}] {self.nom}</p><ul><li>PATH: {self.ligne}</li><li>INFO: {self.info}</li></ul>"
    def color(self):
        if self.sev == "Low":
            return "style='color:#5cd65c'"
        elif self.sev == "Medium":
            return "style='color:#ff8000'"
        elif self.sev == "High":
            return "style='color:#ff3300'"
        else:
            return "style='color:#cc3399'"

class SnykAnalyser(object):
    def __init__(self,file:str="snyk.json") -> None:
        self.jsonFile = fromJSON(file)
        self.ruleIndex = []
        self.score = [400,700,900,1001]
        self.etiquette = ["Low","Medium","High","Critical"]
        self.nbVuln = 0
        self.vuln:Vulnerabilite = []

    def __str__(self) -> str:
        for i in self.vuln:
            print(str(i))
        return f"<script>var vul =  {self.nbVuln}; document.getElementById('issue').innerHTML = 'Issues : ' + vul; </script>"

    def __call__(self):
        snyk = self.jsonFile["runs"][0]
        rules = snyk["tool"]["driver"]["rules"]

        for i in rules:
            self.ruleIndex.append(i["shortDescription"]["text"])
        
        vuln = snyk["results"]

        for i in vuln:
            self.nbVuln += 1
            name = self.ruleIndex[i['ruleIndex']]
            score = int(float(i['properties']['priorityScore']))
            severity = ""
            for j in range(len(self.score)-1,-1,-1):
                if score>=self.score[j]:
                    severity = self.etiquette[j+1]
                    break
            if(severity == ""):
                severity = self.etiquette[0]
            info = i['message']['text']
            ligne = f"{i['locations'][0]['physicalLocation']['artifactLocation']['uri']}, line {i['locations'][0]['physicalLocation']['region']['startLine']}"
            tmp = Vulnerabilite(name,severity,score,info,ligne)
            self.vuln.append(tmp)
        self.vuln.sort(key=lambda x: x.ind)

myAnalyser = SnykAnalyser()

myAnalyser()

print("""
<!DOCTYPE html>
      <html>
        <head>
            <title>Code Issues</title>
      <style>
    .button {
            background-color: #4CAF50; /* Green */
            border: none;
            color: white;
            padding: 15px 32px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 4px 2px;
            transition-duration: 0.4s;
            cursor: pointer;
            border-radius: 8px;
            border: 2px solid #4CAF50; /* Green border */
        }

        /* Hover effect */
        .button:hover {
            background-color: white;
            color: #4CAF50;
        }
    </style>
        </head>
        <body>
      <a href="./index.html">
    <!-- Button element -->
    <button class="button">Retour sur le menus principale</button>
    </a>
      
      <div><h1 id='issue'></h1></div>
""")

print(myAnalyser)

print("""
      </body>
      </html>
""")