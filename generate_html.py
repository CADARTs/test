from io import TextIOWrapper
import json
import sys

def recupJson(path:str):
    f = open(path,'r')
    return f.read()


class Vulnerabilite(object):
    def __init__(self,file:str,silent:bool):
        self.f = file
        self.check = False
        self.vulnerabilities = [0,0,0,0,0]
        self.silent = silent
    def __repr__(self) -> str:
        return f"Nombre de vulnérabilité :\nCritical : {self.vulnerabilities[0]}\nHigh : {self.vulnerabilities[1]}\nMedium : {self.vulnerabilities[2]}\nLow : {self.vulnerabilities[3]}\nInsignifiante : {self.vulnerabilities[4]}"
    def recupVuln(self):
        if self.silent != True:
            print("Check vulnerabilities ...")
        self.check = True
        tmpJson = json.loads(self.f)
        mat = tmpJson['matches']
        for i in mat:
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
        if self.silent != True:
            print("Done Checking")
    
    def printAll(self):
        if self.check == False:
            self.recupVuln()
        print(f"var crit = {self.vulnerabilities[0]};")
        print(f"var hig = {self.vulnerabilities[1]};")
        print(f"var med = {self.vulnerabilities[2]};")
        print(f"var low = {self.vulnerabilities[3]};")
        print(f"var ins = {self.vulnerabilities[4]};")

    def returnAll(self):
        if self.check == False:
            self.recupVuln()
        return f"""var crit = {self.vulnerabilities[0]};
var hig = {self.vulnerabilities[1]};
var med = {self.vulnerabilities[2]};
var low = {self.vulnerabilities[3]};
var ins = {self.vulnerabilities[4]};
var totalVuln = crit + hig + med + low + ins;"""

    def Critical(self):
        if self.check == False:
            self.recupVuln()
        
    
    def High(self):
        if self.check == False:
            self.recupVuln()
        
    
    def Medium(self):
        if self.check == False:
            self.recupVuln()
        
    
    def Low(self):
        if self.check == False:
            self.recupVuln()
        
    
    def Insignifient(self):
        if self.check == False:
            self.recupVuln()
        

def createHTML(vul:Vulnerabilite):
    return

silent = False

if(len(sys.argv)>1):
    if sys.argv[1].lower() == "true":
        silent = True

class Dependancies(object):
    def __init__(self,file:str):
        self.nbDep = 0
        self.f = file
    
    def recupDepend(self):
        tmpJson = json.loads(self.f)
        art = tmpJson['artifacts']
        for i,_ in enumerate(art):
            """
            do nothing just count
            """
        self.nbDep = i+1

    def getNbDep(self):
        self.recupDepend()
        return f"var total = {self.nbDep};"
    

index ="""<!DOCTYPE html>
<!--**This file is automatically generated
-->

<html>
  <head>
    <script type='text/javascript' src='https://www.gstatic.com/charts/loader.js'></script>
    <script type='text/javascript'>""" + Vulnerabilite(recupJson('grypetmp.json'),silent).returnAll() + '\n' + Dependancies(recupJson('syfttmp.json')).getNbDep() +"""\n   google.charts.load('current', {'packages':['corechart']});
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
          ['Vulnérable',     totalVuln],
          ['Ok',      total]
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
  </head>
  <body>
    <div id='piechart' style='width: 900px; height: 500px;'></div>
    <div id='piechart2' style='width: 900px; height: 500px;'></div>
  </body>
</html>

"""
print(index)