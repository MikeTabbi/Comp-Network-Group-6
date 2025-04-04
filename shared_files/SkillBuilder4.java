
/**
 * SkillBuilder5 is a class for completing the Skill
 * Builder 5 assignment in Java.
 *
 * @author <You>
 * @version 1.0
 */

public class SkillBuilder4 {


    public static String findTYPattern(String s) {
        int state = 0;
        String substring ="";
        char[] chars = s.toCharArray();

        for(int i = 0; i < chars.length;i++){
            char c = chars[i];

            if(state==0){
                if(c=='t'||c=='T'){
                    substring+=c;
                    state++;
                }

            }
            else if (state==1){
                substring+=c;
                if(c=='y'||c=='Y'){
                    state++;
                }

            }
            else if(state==2){
                return substring;

            }
        }return"";


    }
}
