var url = `https://api.applicationinsights.io/v1/apps/db6ce774-12d0-45af-8ed4-be7445930439/query?query=requests
| where timestamp > datetime(14 Dec 22 23:59) and operation_Name == 'POST Apply/Prism' and client_CountryOrRegion != ""
| project client_CountryOrRegion`;

var response = fetch(url, {
    method: 'GET',
    headers:{
      'X-Api-Key': '6w80zqlax2iaaqvn7cvgrdwtjno0qaqgsphmn4yj' // its a read only key so don't get any dirty ideas.
    }                                                         // the application insights its reading from is ONLY for this demo. No sensitive data is stored at this api
  }).then((data) =>{                                          
    return data.json()
  }).then((data) => {
    return data["tables"][0]["rows"];
  });

export default await response;