from io import TextIOWrapper
import json
import sys

def recupJson(path:str)-> TextIOWrapper:
    f = open(path,'r')
    return f.read()

class Version(object):
    def __init__(self,version):
        if(version==""):
            self.version = None
        elif(isinstance(version,Version)):
            self = version
        else:
            self.version = version.split('.')
    
    def __repr__(self) -> str:
        return f"{self.version}"

    def __str__(self) -> str:
        ret:str = ""
        if self.version != None:
            for i,vers in enumerate(self.version):
                if i == len(self.version)-1:
                    ret += vers
                else: 
                    ret+= vers + "."
        return ret

    def versionPlusGrande(self,o:object):
        if not isinstance(o,Version):
            return NotImplemented
        if(o.version == None):
            return self
        if(self.version == None):
            return o
        if(len(o.version)>=len(self.version)):
            for vers1,vers2 in zip(o.version,self.version):
                vers1 = int(vers1)
                vers2 = int(vers2)
                if(vers1!=vers2):
                    if(vers1>vers2):
                        return o
                    else:
                        return self
            return o
        else:
            for vers1,vers2 in zip(o.version,self.version):
                vers1 = int(vers1)
                vers2 = int(vers2)
                if(vers1!=vers2):
                    if(vers1>vers2):
                        return o
                    else:
                        return self
            return self
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other,Version):
            return False
        if(other.version== None):
            return False
        if(self.version == None):
            return False
        for vers1,vers2 in zip(other.version,self.version):
            if(vers1!=vers2):
                return False
        return True
    
class Vulnerable(object):
    def __init__(self,id:str,lien:str,severe:str,vector:str,fix,nom:str):
        self.nom = nom
        self.id = id
        self.lien = lien
        self.severite = severe
        self.vector = vector
        self.fix = Version(fix)
    def __str__(self) -> str:
        return f"Nom: {self.nom}, ID: {self.id}, Lien: {self.lien}, Sévérité: {self.severite}, Vecteur: {self.vector}, Version fixe: {str(self.fix)}"
    
    def printHTML(self):
        if( self.severite =='Critical'):
            color = 'style="color:#b300b3;"'
        elif( self.severite =='High'):
            color = 'style="color:#ff0000;"'
        elif( self.severite =='Medium'):
            color = 'style="color:#ffcc00;"'
        elif( self.severite =='Low'):
            color = 'style="color:#66ff33;"'
        else:
            color = 'style="color:""'
        print(f"<tr><td>{self.nom}</td><td> - </td><td> - </td><td>{str(self.fix)}</td><td><p "+color+f"'>{self.severite}</p></td><td>{self.id}</td><td><a href='{self.lien}'> {self.lien} </a></td><td>{self.vector}</td></tr>")


class ListeVulnerable(object):
    def __init__(self) -> None:
        self.liste:Vulnerable = []

    def recupVuln(self,path):
        tmpVuln:Vulnerable
        tmpJSON = json.loads(recupJson(path))
        mat = tmpJSON['matches']
        for i in mat:
            vuln = i['vulnerability']
            idTmp = vuln['id']
            lien = vuln['dataSource']
            severite = vuln['severity']
            nom = i['artifact']['name']
            if vuln['cvss'] == [] :
                vector = i['matchDetails'][0]['found']['vulnerabilityID']
            else:
                vector = vuln['cvss'][0]['vector']
            
            if(vuln['fix']['state'] == "fixed"):
                version = vuln['fix']['versions'][0]
            else:
                version = ""
            tmpVuln = Vulnerable(idTmp,lien,severite,vector,version,nom)
            self.liste.append(tmpVuln)
    
    def printListe(self):
        for i in self.liste:
            print(i)
        return ""
            
class Dependance(object):
    def __init__(self,Nom:str,version:str) -> None:
        self.Nom = Nom
        self.version:Version = Version(version)
        self.VersionFix:Version = Version("")
        self.LVulnerable:Vulnerable= []
    
    def addVulnerabilite(self,vuln:Vulnerable):
        self.LVulnerable.append(vuln)
        self.VersionFix = self.VersionFix.versionPlusGrande(vuln.fix)
        

    def __str__(self) -> str:
        vuln_str = ', '.join(str(v) for v in self.LVulnerable)
        return f"{self.Nom}: {self.version}, {self.VersionFix}, [{vuln_str}]"
    
    def printHTML(self):
        print(f"<tr><td>{self.Nom}</td><td>{self.version}</td><td>{len(self.LVulnerable)}</td><td>{str(self.VersionFix)}</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>")
        for i in self.LVulnerable:
            i.printHTML()

class ListeDependance(object):
    def __init__(self) -> None:
        self.liste = []
    
    def recupDependance(self, path, LVuln):
        severities = ['Critical', 'High', 'Medium', 'Low']
        severity_order = {severity: index for index, severity in enumerate(severities)}
        tmpJSON = json.loads(recupJson(path))
        art = tmpJSON['artifacts']
        for i in art:
            trouve = False
            name = i['name']
            version = i['version']
            for j in self.liste:
                if j.Nom == name and j.version == Version(version):
                    trouve = True
            if trouve==False:
                
                tmpDep = Dependance(name, version)
                for Vuln in LVuln.liste:
                    if name == Vuln.nom:
                        tmpDep.addVulnerabilite(Vuln)
                tmpDep.LVulnerable.sort(key=lambda x: severity_order.get(x.severite, float('inf')))
                self.liste.append(tmpDep)

    def printHTML(self):
        print("<table classe='t1'>")
        print("<tr><td>Nom</td><td>Version</td><td>Nombre de vulnérabilité</td><td>Version Fix</td><td>Sévérité</td><td>ID</td><td>Lien</td><td>Vector</td></tr>")
        for i in self.liste:
            i.printHTML()
        print("</table>")

            


grype = ListeVulnerable()

grype.recupVuln("./grypetmp.json")

html = ListeDependance()

html.recupDependance("./syfttmp.json",grype)

html.liste = sorted(html.liste,key=lambda x:len(x.LVulnerable),reverse=True)

print("""
<!DOCTYPE html>
<!--**This file is automatically generated
-->

<html>
    <head>
        <title>Tableau</title>
        <style>
      
     #Medium{
      color :'#ffcc00';
     }
      
     #High{
      color :'#ff0000';
     }
      
      #Critical{
        color :'#b300b3';
      }

      #Low{
      color :'#66ff33';
      }

      table{
  border-collapse: collapse;
  width: 300px;
  margin-bottom: 20px;
}
.t1{
  table-layout: fixed;
}

th, td{
  border: 1px solid black;
  padding: 10px;
  white-space: nowrap;
  text-align : center;
}
        </style>
    </head>
    <body>
""")

html.printHTML()

print("""
      <button>
      <a href="./index.html">Retourner vers les diagrammes circulaires</a>
    </button>
    </body>
</html>
""")