/*
  Class RequirementsParser parse all require arguments
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;

import java.io.File;
import java.io.FileReader;
import java.util.*;

public class RequirementsParser {
    private final Map<String, Integer> requirements = new Hashtable<>();

    /**
     * Parses requirements json file into local structures requirements
     * Parser is trying to get all requirements from file "/data/requirements.json". If file is missing, it loads requirements from user input
     * @param filename file path
     * @throws Exception no such file found or bad JSON structure
     */
    public RequirementsParser(String filename) throws Exception {
        File requirementsFile = new File(filename); // file for check if exists
        RequirementsParser reqParser = null;
        JSONArray tmp;
        if (!requirementsFile.exists()) {
            Scanner scanner = new Scanner(System.in);
            System.out.println("--------------- Loading requests from the user ------------------------");
            System.out.println("To stop input, press the enter key");
            System.out.println("-----------------------------------------");
            StringBuilder stdinRequirements = new StringBuilder("[");
            int iterator = 1;
            while (true) {
                System.out.println("Enter an item name " + iterator + ":");
                String name = scanner.nextLine();
                //stop if empty line
                if (name == null || name.equals("")) {
                    break;
                }
                System.out.println("Enter an item count " + iterator + ":");
                String amount = scanner.nextLine();
                //stop if empty line
                if (amount == null || amount.equals("")) {
                    break;
                }
                stdinRequirements.append("{");
                stdinRequirements.append("\"name\": \"");
                stdinRequirements.append(name);
                stdinRequirements.append("\", \"amount\": ");
                stdinRequirements.append(amount);
                stdinRequirements.append("}");
                iterator++;
            }
            scanner.close();
            stdinRequirements.append("]");

            tmp = (JSONArray) new JSONParser().parse(String.valueOf(stdinRequirements));
        } else {
            tmp = (JSONArray) new JSONParser().parse(new FileReader(filename));
        }

        for (Object o : tmp) {
            Map itr1 = ((Map) o);
            String name = itr1.get("name").toString();
            int amount = Integer.parseInt(itr1.get("amount").toString());
            requirements.put(name, amount);
        }
    }

    /**
     * Get all parsed requirements
     * @return parsed requirements
     */
    public Map<String, Integer> getRequirements() {
        return requirements;
    }
}