from io import TextIOWrapper
import json
import sys

def recupJson(path:str):
    f = open(path,'r')
    return f.read()

class Version(object):
    """
    Class Version : permet de définir une version.\n
    Une version est de type "10.5.1" pour la comparé il suffit demettre chaque numéro dans un tableau [10,5,1] il suffit par la suite de comparé chaque chant avec une autre version.\n
    """
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


class Vulnerabilite(object):
    def __init__(self,file:str):
        self.f = file
        self.check = False
        self.vulnerabilities = [0,0,0,0,0]
        self.LNom = []
    def __repr__(self) -> str:
        return f"Nombre de vulnérabilité :\nCritical : {self.vulnerabilities[0]}\nHigh : {self.vulnerabilities[1]}\nMedium : {self.vulnerabilities[2]}\nLow : {self.vulnerabilities[3]}\nInsignifiante : {self.vulnerabilities[4]}"
    def recupVuln(self):
        self.check = True
        tmpJson = json.loads(self.f)
        mat = tmpJson['matches']
        for i in mat:
            nom = i['artifact']['name']
            if nom not in self.LNom:
                self.LNom.append(nom)
            vul = i['vulnerability']
            if( vul['severity'] =='Critical'):
                self.vulnerabilities[0]+=1
            elif( vul['severity'] =='High'):
                self.vulnerabilities[1]+=1
            elif( vul['severity'] =='Medium'):
                self.vulnerabilities[2]+=1
            elif( vul['severity'] =='Low'):
                self.vulnerabilities[3]+=1
            else:
                self.vulnerabilities[4]+=1

    def returnAll(self):
        if self.check == False:
            self.recupVuln()
        return f"""var crit = {self.vulnerabilities[0]};
var hig = {self.vulnerabilities[1]};
var med = {self.vulnerabilities[2]};
var low = {self.vulnerabilities[3]};
var ins = {self.vulnerabilities[4]};
var totalVuln = crit + hig + med + low + ins;"""
        

class Dependancies(object):
    def __init__(self,file:str):
        self.nbDep = 0
        self.f = file
        self.LNom = []
        self.LVerion = []
    
    def recupDepend(self):
        tmpJson = json.loads(self.f)
        art = tmpJson['artifacts']
        for i in art:
            trouve = False
            name = i['name']
            version = i['version']
            for j,tmp in enumerate(self.LNom):
                if name == tmp and self.LVerion[j]==version:
                    trouve = True
            if trouve != True:
                self.LNom.append(name)
                self.LVerion.append(Version(version))
        


    def getNbDep(self):
        self.recupDepend()
        return f"var total = {len(self.LNom)};"
    
    def getNbDepNonVuln(self,LVuln:Vulnerabilite):
        """"
        Retourne le nombre de dépendance qui a aucune vulnérabilité
        """
        return f"var totalSVuln = {len(self.LNom)-len(self.LVuln.LNom)}"
            

    def getNbDepVuln(self,LVuln:Vulnerabilite):
        return f"var totalWVuln = {len(self.LVuln.LNom)}"
    

dep =  Dependancies(recupJson('syfttmp.json'))
vul = Vulnerabilite(recupJson('grypetmp.json'))

index ="""<!DOCTYPE html>
<!--**This file is automatically generated-->
<html>
  <head>
    <script type='text/javascript' src='https://www.gstatic.com/charts/loader.js'></script>
    <script type='text/javascript'>""" + vul.returnAll() + '\n' + dep.getNbDep() +"\n" +dep.getNbDepVuln(vul)+ "\n"+ dep.getNbDepNonVuln(vul) +"""\n   google.charts.load('current', {'packages':['corechart']});
      google.charts.setOnLoadCallback(drawChartVuln);
      google.charts.setOnLoadCallback(drawChart);

      function drawChartVuln() {

        var data = google.visualization.arrayToDataTable([
          ['Dangerosité', 'Nb'],
          ['Critique',     crit],
          ['Élevé',      hig],
          ['Moyenne',  med],
          ['Légère', low],
          ['Insignifiante',    ins]
        ]);

        var options = {
          title: 'Grype Summary',
          slices:{
            0:{color :'#b300b3',offset : 0.1},
            1:{color :'#ff0000'},
            2:{color :'#ffcc00'},
            3:{color :'#66ff33'},
            4:{color :'#a6a6a6'}
          }
        };

        var chart = new google.visualization.PieChart(document.getElementById('piechart'));

        chart.draw(data, options);
      }

      function drawChart() {

        var data = google.visualization.arrayToDataTable([
          ['Dep', 'Nb'],
          ['Vulnérable',     totalWVuln],
          ['Ok',      totalSVuln]
        ]);

        var options = {
          title: 'Nombre de dépendance : ' + total,
          slices: {
            0: {offset : 0.1, color: 'red'},
            1: {color: '#0066cc'}
          }
        };

        var chart = new google.visualization.PieChart(document.getElementById('piechart2'));

        chart.draw(data, options);
     }
    </script>
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
  <a href="./dependance.html">
    <!-- Button element -->
    <button class="button">Voir les dépendances</button>
    </a>
    <div id='piechart' style='width: 900px; height: 500px;'></div>
    <div id='piechart2' style='width: 900px; height: 500px;'></div>

    
  </body>
</html>

"""
print(index)