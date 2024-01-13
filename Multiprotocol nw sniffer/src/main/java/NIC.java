import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class NIC {
    public static List<PcapNetworkInterface> getNIC() throws IOException {
        List<PcapNetworkInterface> allNIC = null;
        try {
            allNIC = Pcaps.findAllDevs();

        } catch (PcapNativeException e) {
            throw new IOException(e.getMessage());
        }

        if (allNIC == null || allNIC.isEmpty()) {
            throw new IOException("No NIF to capture.");
        }
        return allNIC;
    }

    public static String[] getNICNames(List<PcapNetworkInterface> nic) {
        ArrayList<String> list = new ArrayList<>();
        for(PcapNetworkInterface ele: nic){
            String s = ele.toString();
            int startIndex = s.indexOf("description:")+14;
            list.add(s.substring(startIndex,s.indexOf("]",startIndex)));
        }
        String[] ans = new String[list.size()];
        int i = 0;
        for (String ele: list){
            ans[i] = ele;
            i++;
        }
        return ans;
    }

    public static PcapNetworkInterface getSelectedNIC(List<PcapNetworkInterface>nic,String myNIC){
        for(PcapNetworkInterface ele: nic){
            if(ele.toString().contains(myNIC)) return ele;
        }
        return null;
    }
}
