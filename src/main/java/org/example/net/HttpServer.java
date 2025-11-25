package org.example.net;




import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/chain")
public class HttpServer {



    @PostMapping("/sales")
    public String submitSales(@RequestBody SalesRequest req) {
        //containerManager.submitSales(req.merchantId, req.amount);
        return "上链成功！当前容器: " ;
    }

    static class SalesRequest {
        public String merchantId;
        public double amount;
    }

    @GetMapping("/status")
    public String status() {
        return "QubeChain运行中，当前容器: ";
    }
}