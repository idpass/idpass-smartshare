package org.idpass.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import org.idpass.smartshare.bluetooth.Utils
import org.idpass.app.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
    }

    override fun onStart() {
        super.onStart()
        // Check Permissions
        Utils.checkPermissions(this)
        // Placeholder scan button
        binding.btnScan.setOnClickListener {
            Snackbar.make(binding.root, "Not yet implemented.", Snackbar.LENGTH_SHORT).show()
        }
    }
}
